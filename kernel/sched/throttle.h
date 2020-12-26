#ifndef __THROTTLE_H__
#define __THROTTLE_H__

#ifdef CONFIG_SCHED_THROTTLE

#define K1			1000ULL
#define M1			(K1 * K1)
#define G1			(K1 * K1 * K1)

#define	TH_MAX_EVENTS		5
#define	TH_MAX_COUNT		(0xffffffffULL)
#define TH_EVT_TABLE_HDR	"%-10s | %-10s | %-10s | %-10s\n"
#define TH_EVT_TABLE_FMT	"%-10d | %-10s | 0x%-8x | %-10llu\n"

#define TH_CPU_TABLE_HDR	"%-10s | %-10s\n"
#define TH_CPU_TABLE_FMT	"%-10d | %-10s\n"
#define PRINT_STATE(cinfo)					\
		(cinfo->th_running? "Active":"Inactive")

#define TH_DEBUG
#ifdef TH_DEBUG
#define th_debug(level, format, ...)				\
do {								\
	if (th_debug_level >= level)				\
		trace_printk(format, ##__VA_ARGS__);		\
} while (0);
#else
#define th_debug(level, format, ...)
#endif

typedef enum {
	INITIALIZE,
	START,
	STOP,
	REGULATE,
	RELEASE
} th_work_t;

typedef enum {
	USER,
	RTG
} th_event_t;

static char* event_types [] = {
	"User",
	"RT-Gang"
};

struct th_event_info {
	th_event_t		type;
	int			id;
	u64			budget;
	u64			count_till_now;
	struct perf_event	*event;
	struct list_head	list;
};

struct th_work_info {
	th_work_t		type;
	struct th_event_info	ev_info;
	bool			do_work;
};

struct th_core_stats {
	u64			ticks_till_now;
	u64			throttle_duration;
	int			throttle_periods;
};

struct th_core_info {
	struct th_core_stats	stats;

	/* HRTIMER relted fields */
	struct hrtimer		hrtimer;
	ktime_t			period_in_ktime;

	/* Throttling related fields */
	bool			th_initialized;
	bool			th_running;
	int			th_regulated_events;
	struct list_head	events;

	struct irq_work		pending;
	wait_queue_head_t	throttle_evt;
	bool			throttle_core;
	struct task_struct	*throttle_thread;
	struct task_struct	*throttled_task;

	wait_queue_head_t	work_evt;
	struct th_work_info	work_info;
	struct task_struct	*worker_thread;
};

/* Interface functions for runtime framework management */
void th_start_framework(void);
void th_stop_framework(void);
void th_regulate_event(int event_id, u64 budget);
void th_release_event(int event_id);
void th_enable_framework(void);
void th_disable_framework(void);

#endif /* CONFIG_SCHED_THROTTLE */

#endif /* __THROTTLE_H__ */
