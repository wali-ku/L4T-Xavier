/*
 * kernel/sched/throttle.c
 *
 * Best-Effort Task Throttling Framework
 *
 * Copyright (C) 2019 CSL-KU
 * 2019-03-23	Integration of BWLOCK++ throttling framework into the scheduler
 * 2019-03-25	Enable runtime selection of throttling event
 * 2019-03-26	Support up-to 2 throttling events simultaneously
 * 2019-03-27	Support variable number of throttling events
 * 2019-03-27	Code refactoring and cleanup
 * 2019-03-29	Further refactoring to create an internal (kernel) interface
 * 2019-03-30	Integrate with the RT-Gang framework
 * 2019-07-07	Create automatic regulation events for bandwidth throttling
 */

#include "sched.h"
#include "throttle.h"

#include <linux/perf_event.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>

#ifdef CONFIG_SCHED_RTGANG
#include "rtg_throttle.h"
#endif

/*
 * Globals: Define various global variables
 */
struct th_core_info __percpu	*th_core_info;

/*
 * Throttle fair scheduler punishment factor
 * default: 0 (No TFS)
 */
static int			th_tfs_factor = 0;

/*
 * Current debug level
 * default: 0 (No debug messages)
 */
static int			th_debug_level = 0;

/*
 * Period of throttling tick in us
 * default: 1ms
 */
static int			th_period_us = 1000;
static bool			th_initialized = false;

/*
 * Local helper functions: Per-core framework management
 */
static void th_init_framework(void);
static inline void th_init_on_this_cpu(void);
static inline void th_start_on_this_cpu(void);
static inline void th_stop_on_this_cpu(void);
static inline void th_regulate_on_this_cpu(struct th_work_info *info);
static inline void th_release_on_this_cpu(int event_id);

/* Entry point of kth_worker thread */
static int th_worker_thread(void *params);

/* Entry point of kthrottle thread */
static int th_throttle_thread(void *params);

/* Perf event overflow handler */
static void th_event_overflow_helper(struct perf_event *event,
			struct perf_sample_data *data, struct pt_regs *regs);
static void th_event_overflow_callback(struct irq_work* entry);

/* Helper function to lookup an event in the event list */
static struct th_event_info* lookup_event(int event_id, int cpu_id);

/* HR-Tick handler */
static enum hrtimer_restart th_timer_callback(struct hrtimer *timer);

/* Debugfs interface management */
static ssize_t th_write(struct file *filp, const char __user *ubuf, size_t cnt,
		loff_t *ppos);
static int th_show(struct seq_file *m, void *v);
static int th_open(struct inode *inode, struct file *filp);

/*
 * th_start_hr_tick - Start HR-Timer tick on "THIS" CPU
 */
static inline void th_start_hr_tick(void)
{
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	hrtimer_start(&cinfo->hrtimer, cinfo->period_in_ktime,
			HRTIMER_MODE_REL_PINNED);
	th_debug(1, "th_hr_tick_start\n");

	return;
}

/*
 * th_stop_hr_tick - Stop HR-Timer tick on "THIS" CPU
 */
static inline void th_stop_hr_tick(void)
{
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	hrtimer_cancel(&cinfo->hrtimer);
	th_debug(1, "th_hr_tick_stop\n");

	return;
}

/*
 * th_start_counter - Start a specific perf counter on "THIS" CPU
 */
static inline void th_start_counter(struct th_event_info *ev_info)
{
	perf_event_enable(ev_info->event);
	ev_info->event->pmu->add(ev_info->event, PERF_EF_START);
	th_debug(1, "th_counter_start: event_id=0x%x\n", ev_info->id);

	return;
}

/*
 * th_stop_counter - Stop a specific perf counter on "THIS" CPU
 */
static inline void th_stop_counter(struct th_event_info *ev_info)
{
	perf_event_disable(ev_info->event);
	ev_info->event->pmu->stop(ev_info->event, PERF_EF_UPDATE);
	ev_info->event->pmu->del(ev_info->event, 0);
	th_debug(1, "th_counter_stop: event_id=0x%x\n", ev_info->id);

	return;
}

/*
 * th_event_count - Return current count of a regulated perf event
 */
static inline u64 th_event_count(struct perf_event *event)
{
	return local64_read(&event->count) +
		atomic64_read(&event->child_count);
}

/*
 * th_init_counter - Create perf kernel counter for a regulated event
 *
 * The counter is created inactive and must later be started explicitly.
 */
static inline struct perf_event* th_init_counter(struct th_event_info* ev_info)
{
	int cpu = smp_processor_id();
	struct perf_event *event = NULL;
	struct perf_event_attr sched_perf_hw_attr = {
		.type		= PERF_TYPE_HARDWARE,
		.config		= PERF_COUNT_HW_CACHE_MISSES,
		.size		= sizeof (struct perf_event_attr),
		.pinned		= 1,
		.disabled	= 1,
		.exclude_kernel	= 1,
		.sample_period	= ev_info->budget,
	};

	event = perf_event_create_kernel_counter(&sched_perf_hw_attr, cpu,
					NULL, th_event_overflow_helper, NULL);

	return event;
}

/*
 * th_init_on_this_cpu - Initialize throttling framework on "THIS" CPU
 *
 * Create throttling event and initialize throttle thread. Create high
 * resoultion timer for periodic framework management. Also create rtgang
 * regulation events.
 */
static inline void th_init_on_this_cpu(void)
{
	int i = smp_processor_id();
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	cinfo->throttle_core = false;
	init_waitqueue_head(&cinfo->throttle_evt);
	init_irq_work(&cinfo->pending, th_event_overflow_callback);

	cinfo->throttle_thread = kthread_create_on_node(th_throttle_thread,
			NULL, cpu_to_node(i), "kthrottle/%d", i);
	kthread_bind(cinfo->throttle_thread, i);
	wake_up_process(cinfo->throttle_thread);

	cinfo->period_in_ktime = ktime_set(0, th_period_us * K1);
	hrtimer_init(&cinfo->hrtimer, CLOCK_MONOTONIC,
			HRTIMER_MODE_REL_PINNED);
	(&cinfo->hrtimer)->function = &th_timer_callback;

#ifdef CONFIG_SCHED_RTGANG
	th_rtg_create_event(TH_RTG_EVT_ID, TH_RTG_EVT_MAX_BUDGET);
#endif

	cinfo->th_initialized = true;
	th_debug(1, "th_init_pass\n");

	return;
}

/*
 * th_start_on_this_cpu - Start throttling framework on "THIS" CPU
 *
 * Start the HR-timer and enable performance counters for all regulated events.
 * Can be invoked as needed during runtime.
 */
static inline void th_start_on_this_cpu(void)
{
	struct th_event_info *curr;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	list_for_each_entry(curr, &cinfo->events, list)
		th_start_counter(curr);

	th_start_hr_tick();
	cinfo->th_running = true;

	return;
}

/*
 * th_stop_on_this_cpu - Stop the throttling framework on "THIS" CPU
 *
 * Stop the HR-timer and disable all currently active performance counters. Can
 * be invoked as needed during runtime.
 */
static inline void th_stop_on_this_cpu(void)
{
	struct th_event_info *curr;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	list_for_each_entry(curr, &cinfo->events, list)
		th_stop_counter(curr);

	th_stop_hr_tick();
	cinfo->th_running = false;

	return;
}

/* th_regulate_on_this_cpu - Create new regulation event on "THIS" CPU
 *
 * Allocate and populate the event node. Create counter for the event and
 * return event information to the caller for tracking.
 */
static inline void th_regulate_on_this_cpu(struct th_work_info *info)
{
	bool restart_needed = false;
	struct th_event_info *ev_info;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	if (cinfo->th_running) {
		/* Stop the framework while the new event is being created */
		restart_needed = true;
		th_stop_on_this_cpu();
	}

	ev_info = kmalloc(sizeof(struct th_event_info), GFP_KERNEL);
	if (!ev_info) {
		th_debug(0, "Failed to allocate memory for event: "
			"event_id=0x%x\n", info->ev_info.id);
		goto out;
	}

	ev_info->id = info->ev_info.id;
	ev_info->budget = info->ev_info.budget;
	ev_info->type = info->ev_info.type;
	ev_info->event = th_init_counter(ev_info);

	if (!ev_info->event) {
		th_debug(0, "Failed to initialize kernel counter for event: "
			"event_id=0x%x\n", info->ev_info.id);

		kfree(ev_info);
		goto out;
	}

	INIT_LIST_HEAD(&ev_info->list);
	list_add(&ev_info->list, &cinfo->events);
	cinfo->th_regulated_events++;

	th_debug(1, "Event created successfully: event_id=0x%x\n",
		info->ev_info.id);

	if (restart_needed)
		/* Restart the framework */
		th_start_on_this_cpu();

out:
	return;
}

/*
 * th_release_on_this_cpu - Destroy an existing event on "THIS" CPU
 *
 * Release the counter associated with the event and de-allocate its storage.
 */
static inline void th_release_on_this_cpu(int event_id)
{
	int ret;
	bool event_found = false;
	bool restart_needed = false;
	struct th_event_info *curr, *temp;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	if (cinfo->th_running) {
		/* Stop the framework while the event is being released */
		restart_needed = true;
		th_stop_on_this_cpu();
	}

	/* Find the event to be released */
	list_for_each_entry_safe(curr, temp, &cinfo->events, list) {
		if (curr->id != event_id)
			continue;

		event_found = true;
		if (curr->type == RTG) {
			th_debug(0, "RTG event cannot be released: "
				"event_id=0x%x\n", curr->id);
			break;
		}

		ret = perf_event_release_kernel(curr->event);
		if (!!ret) {
			th_debug(0, "Failed to release event: "
				"event_id=0x%x\n", curr->id);
			break;
		}

		list_del(&curr->list);
		kfree(curr);

		th_debug(1, "Successfully released event: event_id=0x%x\n",
			curr->id);
		cinfo->th_regulated_events--;
		break;
	}

	if (!event_found)
		th_debug(0, "Event not found: event_id=0x%x\n", event_id);

	if (restart_needed)
		/* Restart the framework */
		th_start_on_this_cpu();

	return;
}

/*
 * th_start_framework - Start framework on each online CPU
 *
 * Initialize (if needed) and start the framework on each online CPU.
 */
void th_start_framework(void)
{
	int i;
	struct th_core_info *cinfo;

	for_each_online_cpu (i) {
		cinfo = per_cpu_ptr(th_core_info, i);

		if (cinfo->th_running)
			/* Framework is already running */
			continue;

		if (i == smp_processor_id())
			th_start_on_this_cpu();
		else {
			cinfo->work_info.type = START;
			cinfo->work_info.do_work = true;
			wake_up_interruptible(&cinfo->work_evt);
		}
	}

	return;
}

/*
 * th_stop_framework - Stop framework on each online CPU
 */
void th_stop_framework(void)
{
	int i;
	struct th_core_info *cinfo;

	for_each_online_cpu (i) {
		cinfo = per_cpu_ptr(th_core_info, i);

		if (!cinfo->th_running)
			/* Framework is already stopped */
			continue;

		if (i == smp_processor_id())
			th_stop_on_this_cpu();
		else {
			cinfo->work_info.type = STOP;
			cinfo->work_info.do_work = true;
			wake_up_interruptible(&cinfo->work_evt);
		}
	}

	return;
}

/*
 * th_regulate_event - Schedule work for the worker thread to regulate an event
 * on each online CPU
 */
void th_regulate_event(int event_id, u64 budget)
{
	int i;
	struct th_core_info *cinfo;
	struct th_event_info *ev_info;

	/* Create a new regulation event */
	for_each_online_cpu (i) {
		ev_info = lookup_event(event_id, i);
		if (!!ev_info) {
			th_debug(1, "Updating budget: event_id=0x%x "
				"old_budget=%llu new_budget=%llu\n",
				event_id, ev_info->budget, budget);

			ev_info->budget = budget;
			continue;
		}

		/* Create new regulation event */
		cinfo = per_cpu_ptr(th_core_info, i);
		if (cinfo->th_regulated_events >= TH_MAX_EVENTS) {
			th_debug(0, "Cannot create new events.\n");
			return;
		}

		cinfo->work_info.type = REGULATE;
		cinfo->work_info.do_work = true;
		cinfo->work_info.ev_info.id = event_id;
		cinfo->work_info.ev_info.budget = budget;
		cinfo->work_info.ev_info.type = USER;

		if (i == smp_processor_id())
			th_regulate_on_this_cpu(&cinfo->work_info);
		else
			wake_up_interruptible(&cinfo->work_evt);
	}

	return;
}

/*
 * th_regulate_event - Schedule work for the worker thread to release an
 * existing event on each online CPU
 */
void th_release_event(int event_id)
{
	int i;
	struct th_core_info *cinfo;

	for_each_online_cpu (i) {
		cinfo = per_cpu_ptr(th_core_info, i);

		if (i == smp_processor_id())
			th_release_on_this_cpu(event_id);
		else {
			cinfo->work_info.type = RELEASE;
			cinfo->work_info.do_work = true;
			cinfo->work_info.ev_info.id = event_id;
			wake_up_interruptible(&cinfo->work_evt);
		}
	}

	return;
}

static struct th_event_info* lookup_event(int event_id, int cpu_id)
{
	struct th_event_info *curr;
	struct th_core_info *cinfo = per_cpu_ptr(th_core_info, cpu_id);

	list_for_each_entry(curr, &cinfo->events, list) {
		if (curr->id == event_id)
			return curr;
	}

	return NULL;
}

#ifdef CONFIG_SCHED_RTGANG
/*
 * th_rtg_create_event - Create perf event for automatic bandwidth regulation
 * under RT-Gang
 *
 * These events are special in that they are regulated automatically once
 * throttling framework starts and they cannot be removed by the user; only
 * their budgets can be modified.
 */
void th_rtg_create_event(int id, u64 budget)
{
	struct th_work_info winfo;

	winfo.ev_info.id = id;
	winfo.ev_info.budget = budget;
	winfo.ev_info.type = RTG;
	th_regulate_on_this_cpu(&winfo);

	return;
}

/*
 * th_rtg_update_budget - Update budget of automatic regulation events of
 * RT-Gang
 */
void th_rtg_update_budget(u64 evt_budget)
{
	if (th_initialized == false)
		/*
		 * The framework has not been initialized yet. Executing the
		 * following instructions, in this case, will cause kernel
		 * panic since the rtg_event is created during initialization.
		 */
		return;

	th_regulate_event(TH_RTG_EVT_ID, evt_budget);

	return;
}
#endif /* CONFIG_SCHED_RTGANG */

/*
 * th_worker_thread - Per core kernel thread for performing core-specific tasks
 *
 * The work to be performed by this thread is determined by the "work_info"
 * field inside the info structure of this core at the time of invocation.
 */
static int th_worker_thread(void *params)
{
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	while (!kthread_should_stop()) {
		th_debug(3, "th_wthread_wakeup\n");

		switch (cinfo->work_info.type) {
			case INITIALIZE:
				th_init_on_this_cpu();
				break;

			case START:
				th_start_on_this_cpu();
				break;

			case STOP:
				th_stop_on_this_cpu();
				break;

			case REGULATE:
				th_regulate_on_this_cpu(&cinfo->work_info);
				break;

			case RELEASE:
				th_release_on_this_cpu(
						cinfo->work_info.ev_info.id);
				break;

			default:
				th_debug(0, "th_fatal_unknown_work\n");
				break;
		}

		/* Sleep till the next invocation */
		cinfo->work_info.do_work = false;
		wait_event_interruptible(cinfo->work_evt,
				cinfo->work_info.do_work);
	}

	return 0;
}

/*
 * th_throttle_thread - High priority kernel thread for idling this CPU
 *
 * Loop on the flag "throttle_core" in this CPU's info structure. Stop further
 * perf events from happening on this CPU in the current period.
 */
static int th_throttle_thread(void *params)
{
	u64 delta_time;
	ktime_t ts_throttle_start;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);
	static const struct sched_param param = {
		.sched_priority = MAX_USER_RT_PRIO / 2,
	};

	sched_setscheduler(current, SCHED_FIFO, &param);
	th_debug(1, "th_kthrottle_create\n");

	while (!kthread_should_stop()) {
		wait_event_interruptible(cinfo->throttle_evt,
				cinfo->throttle_core || kthread_should_stop());

		th_debug(3, "th_kthread_wakeup\n");
		if (kthread_should_stop())
			break;

		ts_throttle_start = ktime_get();
		while (cinfo->throttle_core && !kthread_should_stop())
			cpu_relax();

		th_debug(3, "th_kthread_sleep\n");
		delta_time = (u64)(ktime_get().tv64 - ts_throttle_start.tv64);
		cinfo->stats.throttle_duration += delta_time;
		cinfo->stats.throttle_periods++;

		if (cinfo->throttled_task) {
			/*
			 * Scale the vruntime of offending task as per the
			 * throttling penalty. This is determined by the TFS
			 * punishment factor.
			 */
			cinfo->throttled_task->se.vruntime += (th_tfs_factor *
					delta_time);
			cinfo->throttled_task = NULL;
		} else
			th_debug(0, "th_fatal_no_task\n");
	}

	return 0;
}

/*
 * th_event_overflow_helper - Perf event overflow handler
 *
 * Invoked in NMI context. Schedule IRQ work for handling overflow on this CPU.
 */
static void th_event_overflow_helper(struct perf_event *event,
		struct perf_sample_data *data, struct pt_regs *regs)
{
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	irq_work_queue(&cinfo->pending);

	return;
}

/*
 * th_event_overflow_callback - IRQ work handler for overflow interrupt
 *
 * Stop the perf events from retriggering the interrupt in this period. Wake
 * up throttle thread on this CPU to stop offending task.
 */
static void th_event_overflow_callback(struct irq_work* entry)
{
	struct perf_event *event;
	struct th_event_info *curr;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);

	if (list_empty(&cinfo->events)) {
		printk(KERN_ERR "[TH_CRIT] No events in overflow handler.\n");
		goto out;
	}

	list_for_each_entry(curr, &cinfo->events, list) {
		event = curr->event;
		event->pmu->stop(event, PERF_EF_UPDATE);
		local64_set((&event->hw.period_left), TH_MAX_COUNT);
		event->pmu->start (event, PERF_EF_RELOAD);
	}

	if (!rt_task(current)) {
		th_debug(2, "th_event_overflow: comm=%s\n", current->comm);
		cinfo->throttle_core = true;
		cinfo->throttled_task = current;
		wake_up_interruptible(&cinfo->throttle_evt);
	}

out:
	return;
}

/*
 * th_timer_callback - HR-Timer tick handler
 *
 * Replenish all the performance counters of this CPU and stop the throttle
 * thread if it is active.
 */
static enum hrtimer_restart th_timer_callback(struct hrtimer *timer)
{
	u64 budget;
	u64 current_event_count;
	struct perf_event *event;
	struct th_event_info *curr;
	struct th_core_info *cinfo = this_cpu_ptr(th_core_info);
	int over_run_cnt = hrtimer_forward_now(timer, cinfo->period_in_ktime);

	if (over_run_cnt == 0)
		/* Timer has not expired yet */
		return HRTIMER_RESTART;

	cinfo->stats.ticks_till_now += over_run_cnt;

	list_for_each_entry(curr, &cinfo->events, list) {
		event = curr->event;
		event->pmu->stop(event, PERF_EF_UPDATE);
		current_event_count = th_event_count(event);
		th_debug(4, "th_hr_tick: event_id=0x%x event_count=%llu\n",
				curr->id, (current_event_count -
				curr->count_till_now));
		curr->count_till_now = current_event_count;

		/*
		 * If the current task on this core is an RT-task; other than
		 * the kthrottle thread, it will not be throttled.
		 */
		if ((rt_task(current) && cinfo->throttle_core != 1))
			budget = TH_MAX_COUNT;
		else
			budget = curr->budget;

		event->hw.sample_period = budget;
		local64_set(&event->hw.period_left, budget);
		event->pmu->start(event, PERF_EF_RELOAD);
	}

	/* This will stop kthrottle */
	cinfo->throttle_core = false;

	return HRTIMER_RESTART;
}

/*
 * th_write - Interface function to read user-input to the debugfs file of
 * throttling framework
 *
 * Check user-prompts against recognized commands. Schedule work for kernel
 * threads on each core based on the command.
 */
static ssize_t th_write(struct file *filp, const char __user *ubuf, size_t cnt,
		loff_t *ppos)
{
	u64 budget;
	char buf[64];
	int event_id;
	int start = 0;
	int new_tfs_factor = 0;
	int new_debug_level = 0;

	if (cnt > 63)
		cnt = 63;

	if (copy_from_user(&buf, ubuf, cnt))
		return -EFAULT;

	if (!strncmp(buf, "init", 4)) {
		if (th_initialized == true) {
			th_debug(1, "[THROTTLE] Framework already initialized!\n");
		} else {
			th_debug(1, "[THROTTLE] Initializing framework...!\n");
			th_init_framework();
			th_initialized = true;
		}
	} else if (!strncmp(buf, "debug", 5)) {
		sscanf(buf + 6, "%d", &new_debug_level);
		th_debug(1, "Update throttling debug level: old=%d new=%d\n",
				th_debug_level, new_debug_level);
		th_debug_level = new_debug_level;
	} else if (!strncmp(buf, "tfs", 3)) {
		sscanf(buf + 4, "%d", &new_tfs_factor);
		th_debug(1, "Update TFS factor: old=%d new=%d\n",
				th_tfs_factor, new_tfs_factor);
		th_tfs_factor = new_tfs_factor;
	} else {
		if (th_initialized == false) {
			th_debug(1, "[THROTTLE] Framework NOT initialized yet!!\n");
		} else if (!strncmp(buf, "start", 5)) {
			sscanf(buf + 6, "%d", &start);

			if (!!start) {
				th_debug(1, "Starting throttling framework\n");
				th_start_framework();
			} else {
				th_debug(1, "Stopping throttling framework\n");
				th_stop_framework();
			}
		} else if (!strncmp(buf, "regulate", 8)) {
			sscanf(buf + 9, "0x%x %llu", &event_id, &budget);
			th_debug(1, "Regulate event: event_id=0x%x budget=%llu\n",
					event_id, budget);
			th_regulate_event(event_id, budget);
		} else if (!strncmp(buf, "release", 7)) {
			sscanf(buf + 8, "0x%x", &event_id);
			th_release_event(event_id);
			th_debug(1, "Release event: event_id=0x%x\n", event_id);
		}
	}

	*ppos += cnt;
	return cnt;
}

/*
 * th_show - Show current configuration of throttling framework
 */
static int th_show(struct seq_file *m, void *v)
{
	int i = 0;
	struct th_event_info *curr;
	struct th_core_info *cinfo;

	if (th_initialized == false) {
		seq_printf(m, "[NOTICE] Please initialize the framework!\n");
		return 0;
	}

	seq_printf(m, "==================== Throttle Control Interface\n");
	seq_printf(m, "%-20s: %d\n", "Initialized", th_initialized? 1:0);
	seq_printf(m, "%-20s: %d\n", "Debug Level", th_debug_level);
	seq_printf(m, "%-20s: %d\n", "TFS Factor", th_tfs_factor);

	seq_printf(m, "\n");
	seq_printf(m, "==================== Per Core Framework State\n");
	seq_printf(m, TH_CPU_TABLE_HDR, "CPU", "State");
	seq_printf(m, "-------------------------------------------------\n");

	for_each_online_cpu (i) {
		cinfo = per_cpu_ptr(th_core_info, i);
		seq_printf(m, TH_CPU_TABLE_FMT, i, PRINT_STATE(cinfo));
	}

	i = 0;
	seq_printf(m, "\n");
	seq_printf(m, "==================== Regulation Events\n");
	seq_printf(m, TH_EVT_TABLE_HDR, "Event", "TYPE", "ID", "Budget");
	seq_printf(m, "-------------------------------------------------\n");

	cinfo = per_cpu_ptr(th_core_info, 0);
	if (!list_empty(&cinfo->events)) {
		list_for_each_entry(curr, &cinfo->events, list) {
			seq_printf(m, TH_EVT_TABLE_FMT, i,
				event_types[curr->type], curr->id,
				curr->budget);
			i++;
		}
	}

	seq_printf(m, "\n");
	return 0;
}

static int th_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, th_show, NULL);
}

static const struct file_operations th_fops = {
	.open		= th_open,
	.write		= th_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void th_init_framework(void) {
	int i;
	struct th_core_info *cinfo;

	for_each_online_cpu (i) {
		cinfo = per_cpu_ptr(th_core_info, i);
		memset(cinfo, 0, sizeof(struct th_core_info));
		INIT_LIST_HEAD(&cinfo->events);

		cinfo->work_info.type = INITIALIZE;
		cinfo->work_info.do_work = true;

		init_waitqueue_head(&cinfo->work_evt);
		cinfo->worker_thread = kthread_create_on_node(th_worker_thread, NULL,
							cpu_to_node(i),
							"kth_worker/%d", i);
		kthread_bind(cinfo->worker_thread, i);

		/* Wake up worker thread to do core specific initialization */
		wake_up_process(cinfo->worker_thread);
	}
}

/*
 * th_init_framework - Initialize the bare minimum data-structures and
 * interface of throttling framework
 */
static int __init th_init_control(void)
{
	struct dentry *dir;
	umode_t mode = S_IFREG | S_IRUSR | S_IWUSR;

	th_core_info = alloc_percpu(struct th_core_info);
	smp_mb();

	dir = debugfs_create_dir("throttle", NULL);
	if (!dir)
		return PTR_ERR(dir);

	if (!debugfs_create_file("control", mode, dir, NULL, &th_fops))
		goto fail;

	return 0;
fail:
	debugfs_remove_recursive(dir);
	return -ENOMEM;
}

late_initcall(th_init_control);
