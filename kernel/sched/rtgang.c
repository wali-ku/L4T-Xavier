/*
 * kernel/sched/rtgang.c
 *
 * Real-Time Gang Scheduling Framework
 *
 * Copyright (C) 2019 CSL-KU
 * 2019-03-28	Separation of RT-Gang from scheduler core
 * 2019-03-29	Support EDF tasks (SCHED_DEADLINE)
 * 2019-03-29	Conditionally compile RT-Gang into kernel
 * 2019-03-30	Integrate with the throttling framework
 */
#include "sched.h"
#include "rtgang.h"
#include <linux/debugfs.h>
#include <linux/syscalls.h>

#ifdef CONFIG_SCHED_THROTTLE
#include "rtg_throttle.h"
#endif

/*
 * Global variables
 */
struct rtgang_lock rtgang_lock;
struct rtgang_lock *rtg_lock = &rtgang_lock;

/*
 * Current debug level
 * Default: 0 (No debug messages)
 */
int rtg_debug_level = 0;

#ifdef CONFIG_SCHED_THROTTLE
/*
 *
 * Default budget for throttling best effort tasks when a real-time gang is
 * running.
 */
u64 rtg_throttle_budget = TH_RTG_EVT_DEFAULT_BUDGET;
#endif

/*
 * gang_lock_cpu - Acquire RT-Gang lock on behalf of the thread
 */
static inline void gang_lock_cpu(struct task_struct *thread)
{
	int cpu = smp_processor_id();

	cpumask_set_cpu(cpu, rtg_lock->locked_cores);
	rtg_lock->gthreads[cpu] = thread;

	return;
}

/*
 * resched_cpus - Send rescheduling interrupt(s) to CPUs in mask
 */
static inline void resched_cpus(cpumask_var_t mask)
{
	int cpu;
	int this_cpu = smp_processor_id();

	for_each_cpu (cpu, mask) {
		rtg_trace_printk(RTG_LEVEL_ALL, "    event=resched_ipi "
				"to_cpu=%d\n", cpu);

		if (cpu == this_cpu)
			continue;

		resched_cpu_force(cpu, NULL);
	}

	return;
}

/*
 * do_gang_preemption - Preempt currently running executing gang on behalf of
 * 'next' gang
 *
 * Acquire RT-Gang lock on behalf of 'next' gang
 */
static inline void do_gang_preemption(struct task_struct *next)
{
	int cpu;
	int this_cpu = smp_processor_id();

	for_each_cpu (cpu, rtg_lock->locked_cores) {
		WARN_ON(rtg_lock->gthreads [cpu] == NULL);

		if (cpu != this_cpu)
			resched_cpu_force(cpu, rtg_lock->gthreads[cpu]);

		rtg_trace_printk(RTG_LEVEL_SUBSTATE, "  event=preempt_thread "
				"on_cpu=%d comm=%s " "pid=%d tgid=%d rtgid=%d "
				"prio=%d\n", cpu,
				rtg_lock->gthreads[cpu]->comm,
				rtg_lock->gthreads[cpu]->pid,
				rtg_lock->gthreads[cpu]->tgid,
				GET_RTG_INFO(rtg_lock->gthreads[cpu])->gid,
				rtg_lock->gthreads[cpu]->prio);

		rtg_lock->gthreads [cpu] = NULL;
	}

	cpumask_clear(rtg_lock->locked_cores);
	gang_lock_cpu(next);
	rtg_lock->leader = next;

	return;
}

/*
 * try_glock_release - Release RT-Gang lock on behalf of 'thread'
 *
 * Send rescheduling interrupt to blocked CPUs if RT-Gang lock is now free.
 */
static inline void try_glock_release(struct task_struct *thread)
{
	int cpu;

	WARN_ON(cpumask_weight(rtg_lock->locked_cores) == 0);

	/*
	 * Release RT-Gang lock of 'prev' task on all cores it may have ran on.
	 * Migrated tasks can hold lock on multiple cores.
	 */
	for_each_cpu (cpu, rtg_lock->locked_cores) {
		if (rtg_lock->gthreads[cpu] == thread) {
			WARN_ON(!rt_prio(thread->prio));

			rtg_lock->gthreads[cpu] = NULL;
			cpumask_clear_cpu(cpu, rtg_lock->locked_cores);

			rtg_trace_printk(RTG_LEVEL_SUBSTATE,
					"  event=lock_rel on_cpu=%d comm=%s "
					"pid=%d " "tgid=%d rtgid=%d prio=%d\n",
					cpu, thread->comm, thread->pid,
					thread->tgid,
					GET_RTG_INFO(thread)->gid,
					thread->prio);
		}
	}

	/*
	 * It is possible for one of the threads of the 'prev' task to be
	 * holding the NPP lock. In that case, there is no point in sending
	 * the rescheduling IPI to the blocked cores.
	 *
	 * We still want to allow the 'prev' thread to release the RT-Gang lock
	 * on this core and go out of schedule if it is done; we don't want to
	 * schedule the blocked cores just yet.
	 */
	if ((rtg_lock->no_preempt == 0) &&
			(cpumask_weight(rtg_lock->locked_cores) == 0)) {
		/* RT-Gang lock is now free. Reschedule blocked cores */
		rtg_log_event(RTG_LEVEL_STATE, thread, "unlock");
		rtg_lock->leader = NULL;
		rtg_lock->busy = false;
		resched_cpus(rtg_lock->blocked_cores);
		cpumask_clear(rtg_lock->blocked_cores);

#ifdef CONFIG_SCHED_THROTTLE
		th_rtg_update_budget(TH_RTG_EVT_MAX_BUDGET);
#endif
	}

	return;
}

/*
 * rtg_try_release_lock - Interface function for releasing RT-Gang lock
 *
 * If the task going out of execution on this CPU is holding RT-Gang lock,
 * release it on the task's behalf and perform necessary book keeping.
 */
void rtg_try_release_lock(struct task_struct *prev)
{
	/*
	 * If 'prev' is a member of the current RT gang, update the
	 * locked_cores mask and release the RT gang lock if necessary.
	 */
	raw_spin_lock(&rtg_lock->access_lock);
	if (rtg_lock->busy)
		try_glock_release(prev);
	raw_spin_unlock(&rtg_lock->access_lock);

	return;
}

/*
 * rtg_try_acquire_lock - Interface function for obtaining RT-Gang lock
 *
 * Check if the next task is eligibile to obtain RT-Gang lock. If not, block
 * the task from executing on this CPU.
 */
int rtg_try_acquire_lock(struct task_struct *next, struct task_struct *prev)
{
	int this_cpu = smp_processor_id();
	int ret = RTG_CONTINUE;

	raw_spin_lock(&rtg_lock->access_lock);
	if (!rtg_lock->busy) {
		/* No RT gang exist currently; begin a new gang */
		BUG_ON(cpumask_weight(rtg_lock->locked_cores) != 0);
		BUG_ON(cpumask_weight(rtg_lock->blocked_cores) != 0);

		rtg_trace_printk(RTG_LEVEL_STATE, "event=lock on_cpu=%d "
				"leader=%s " "pid=%d tgid=%d rtgid=%d "
				"prio=%d\n", this_cpu, next->comm, next->pid,
				next->tgid, GET_RTG_INFO(next)->gid,
				next->prio);

		gang_lock_cpu(next);
		rtg_lock->busy = true;
		rtg_lock->leader = next;

#ifdef CONFIG_SCHED_THROTTLE
		if (GET_RTG_INFO(next)->budget == 0)
			th_rtg_update_budget(rtg_throttle_budget);
		else
			th_rtg_update_budget(GET_RTG_INFO(next)->budget);
#endif

		goto out;
	}

	BUG_ON(cpumask_weight(rtg_lock->locked_cores) == 0);
	if (IS_GANG_MEMBER(next)) {
		/* 'next' is part of the current RT gang */
		rtg_trace_printk(RTG_LEVEL_SUBSTATE, "  event=lock_add "
				"on_cpu=%d member=%s pid=%d tgid=%d rtgid=%d "
				"prio=%d\n", this_cpu, next->comm, next->pid,
				next->tgid, GET_RTG_INFO(next)->gid,
				next->prio);

		gang_lock_cpu(next);
		goto out;
	}

	/*
	 * Gang preemption conditions:
	 *   1. Current gang leader and 'next' task are of same scheduler type
	 *   	1.1. EDF: 'next' has earlier deadline
	 *   	1.2. FIFO: 'next' has higher priority
	 *   2. Current gang leader and 'next' task are of different scheduler
	 *   type and next is an EDF task
	 */
	if (((IS_SAME_CLASS(next, rtg_lock->leader)) &&
		((IS_EDF(next) && IS_EARLIER_EDF(next, rtg_lock->leader)) ||
		(!IS_EDF(next) && IS_HIGHER_PRIO(next, rtg_lock->leader)))) ||
	   ((!IS_SAME_CLASS(next, rtg_lock->leader)) && IS_EDF(next))) {
		/*
		 * This is technically a valid preemption attempt but we may
		 * not want to grant it if the running task currently holds
		 * the NPP lock. In this case, record that HP task is waiting
		 * and disallow preemption at the moment.
		 */
		if (rtg_lock->no_preempt > 0) {
			rtg_lock->hp_waiting = true;
			rtg_log_event(RTG_LEVEL_STATE, next, "npp-block");
			cpumask_set_cpu(this_cpu, rtg_lock->blocked_cores);

			/*
			 * Reacquire the RT-Gang lock on behalf of the 'prev'
			 * thread since it cannot be preempted at the moment.
			 */
			gang_lock_cpu(prev);

			ret = RTG_NPP_BLOCK;
			goto out;
		}

		rtg_log_event(RTG_LEVEL_STATE, next, "preemption");
		do_gang_preemption(next);

		/*
		 * The 'prev' task will now be blocked on this cpu. We must
		 * update the blocked core mask to reflect that.
		 */
		cpumask_set_cpu(this_cpu, rtg_lock->blocked_cores);

#ifdef CONFIG_SCHED_THROTTLE
		if (GET_RTG_INFO(next)->budget == 0)
			th_rtg_update_budget(rtg_throttle_budget);
		else
			th_rtg_update_budget(GET_RTG_INFO(next)->budget);
#endif
	} else {
		/* 'p' has lower priority; blocked */
		if (!cpumask_test_cpu(this_cpu, rtg_lock->blocked_cores)) {
			cpumask_set_cpu(this_cpu, rtg_lock->blocked_cores);
			rtg_log_event(RTG_LEVEL_STATE, next, "block");
		}

		ret = RTG_BLOCK;
	}

out:
	raw_spin_unlock(&rtg_lock->access_lock);
	return ret;
}

SYSCALL_DEFINE1(npplock, int, lock)
{
	int ret = 0;

	if (lock != 0 && lock != 1) {
		printk(KERN_WARNING "[RT-GANG] NPP lock must be 0 or 1!");
		return -EINVAL;
	}

	if (!(IS_RTC(current) || IS_EDF(current))) {
		printk(KERN_WARNING "[RT-GANG] Requesting NPP lock "
				"from non-rt thread!");
		return -EACCES;
	}

	if (!(IS_GANG_MEMBER(current))) {
		printk(KERN_ERR "[RT-GANG] Requesting NPP lock "
				"but task does not have RT-Gang lock!");
		return -EINVAL;
	}

	raw_spin_lock(&rtg_lock->access_lock);

	if (lock == 0) {
		if (rtg_lock->no_preempt == 0) {
			printk(KERN_ERR "[RT-GANG] Trying to release a "
					"free lock!");

			ret = -EPERM;
			goto spin_out;
		}

		rtg_log_event(RTG_LEVEL_STATE, current, "npp-release");
		rtg_lock->no_preempt--;

		/*
		 * Task has come out of non-preemptive critical section and an
		 * HP task is waiting. Reschedule CPUs.
		 */
		if (rtg_lock->no_preempt == 0 && rtg_lock->hp_waiting) {
			rtg_log_event(RTG_LEVEL_SUBSTATE, current,
					"    npp-free");
			rtg_lock->hp_waiting = false;
			resched_cpus(rtg_lock->blocked_cores);
			cpumask_clear(rtg_lock->blocked_cores);
		}
	} else {
		if (rtg_lock->hp_waiting) {
			ret = -EBUSY;
			goto spin_out;
		}

		rtg_log_event(RTG_LEVEL_STATE, current,
				"npp-lock");
		rtg_lock->no_preempt++;
	}

spin_out:
	raw_spin_unlock(&rtg_lock->access_lock);


	return ret;
}

/*
 * rtg_init_lock - Initialize RT-Gang data-structure and interface
 *
 * Called at the end of kernel initialization. Performs bare-minimum setup for
 * using RT-Gang at runtime.
 */
static int __init rtg_init_lock(void)
{
	int i = 0;
	struct dentry *dir;
	umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;

	dir = debugfs_create_dir("rtgang", NULL);
	if (!dir)
		return PTR_ERR(dir);

	if (!debugfs_create_u32("debug_lvl", mode, dir, &rtg_debug_level))
		goto fail;

#ifdef CONFIG_SCHED_THROTTLE
	if (!debugfs_create_u64("throttle_budget", mode, dir,
				&rtg_throttle_budget))
		goto fail;
#endif

	rtg_lock->busy = false;
	rtg_lock->leader = NULL;
	rtg_lock->no_preempt = 0;
	rtg_lock->hp_waiting = false;
	raw_spin_lock_init(&rtg_lock->access_lock);
	zalloc_cpumask_var(&rtg_lock->locked_cores, GFP_KERNEL);
	zalloc_cpumask_var(&rtg_lock->blocked_cores, GFP_KERNEL);

	for (; i < NR_CPUS; i++)
		rtg_lock->gthreads[i] = NULL;

	return 0;
fail:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

late_initcall(rtg_init_lock);
