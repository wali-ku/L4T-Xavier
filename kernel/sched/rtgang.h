#ifndef __RTGANG_H__
#define __RTGANG_H__

#ifdef CONFIG_SCHED_RTGANG

extern int rtg_debug_level;

#define RTG_FIFO_PRIO_THRESHOLD		(50)
#define	RTG_CONTINUE			(0)
#define RTG_BLOCK			(1)
#define RTG_NPP_BLOCK			(2)

#define RTG_FIFO_CHECK(p)					\
	(p->mm && p->prio > RTG_FIFO_PRIO_THRESHOLD)

#define IS_REAL_GANG_MEMBER(p)					\
	(rtg_lock->leader->tgid == p->tgid)

/*
 * FIXME
 * This check is hard-coded to make it easier to handle docker apps.  It is not
 * applicable to the deadline tasks. As long as this check exists in the
 * current form, the rtgang framework MUST NOT be used with deadline tasks.
 */
#define IS_VIRT_GANG_MEMBER(p)					\
	(((GET_RTG_INFO(rtg_lock->leader)->gid != 0) && 	\
		(GET_RTG_INFO(rtg_lock->leader)->gid == 	\
		 GET_RTG_INFO(p)->gid)) ||			\
	  ((GET_RTG_INFO(rtg_lock->leader)->gid == 0) &&	\
		GET_RTG_INFO(p)->gid == 0 &&			\
		rtg_lock->leader->prio == p->prio))

#define IS_GANG_MEMBER(p)					\
	(rtg_lock->busy && (IS_REAL_GANG_MEMBER(p) || IS_VIRT_GANG_MEMBER(p)))

#define IS_SAME_CLASS(p, n)					\
	(p->sched_class == n->sched_class)

#define IS_RTC(p)						\
	(p->sched_class == &rt_sched_class)

#define IS_EDF(p)						\
	(p->sched_class == &dl_sched_class)

#define IS_EARLIER_EDF(p, n)					\
	(dl_time_before(p->dl.deadline, n->dl.deadline))

#define IS_HIGHER_PRIO(p, n)					\
	(p->prio < n->prio)

#define PRINT_SCHED(p)						\
	(IS_EDF(p)? "EDF":"FIFO")

#define PRINT_PRIO(p)						\
	(IS_EDF(p)? p->dl.deadline:(u64)p->prio)

#define RTG_DEBUG
#ifdef RTG_DEBUG
#define rtg_trace_printk(level, format, ...)			\
do {								\
	if (rtg_debug_level >= level) {				\
		char buf[256];					\
		snprintf(buf, 256, "<file=%s line=%d> "		\
			format, __FILE__, __LINE__, 		\
			##__VA_ARGS__);				\
		trace_printk(buf);				\
	}							\
} while (0);

#define rtg_log_event(level, task, event)			\
	rtg_trace_printk(level, "event=%s cpu=%d comm=%s "	\
			"pid=%d tgid=%d rtgid=%d prio=%d\n",	\
			event, smp_processor_id(), task->comm,	\
			task->pid, task->tgid,			\
			GET_RTG_INFO(task)->gid, task->prio)
#else
#define rtg_trace_printk(level, format, ...)
#define rtg_log_event(level, task, event)
#endif

/* Debug Levels */
#define	RTG_LEVEL_CRITICAL		(0)
#define RTG_LEVEL_STATE			(1)
#define RTG_LEVEL_SUBSTATE		(2)
#define RTG_LEVEL_ALL			(3)

struct rtgang_lock {
	bool			busy;
	bool			hp_waiting;
	int			no_preempt;
	raw_spinlock_t		access_lock;
	struct task_struct*	leader;
	struct task_struct*	gthreads [NR_CPUS];
	cpumask_var_t		locked_cores;
	cpumask_var_t		blocked_cores;
};

void rtg_try_release_lock(struct task_struct *prev);
int rtg_try_acquire_lock(struct task_struct *next, struct task_struct *prev);

#endif /* CONFIG_SCHED_RTGANG */

#endif /* __RTGANG_H__ */
