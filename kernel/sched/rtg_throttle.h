#ifndef __RTG_THROTTLE_H__
#define __RTG_THROTTLE_H__

#if defined(CONFIG_SCHED_RTGANG) && defined(CONFIG_SCHED_THROTTLE)

#define ID_TX2				(0x1)
#define ID_PI				(0x2)
#define ID_XAVIER			(0x3)
#define PLATFORM_ID			ID_XAVIER

#if (PLATFORM_ID == ID_TX2 || PLATFORM_ID == ID_PI)
#define TH_RTG_EVT_ID			(0x17)
#elif (PLATFORM_ID == ID_XAVIER)
#define TH_RTG_EVT_ID			(0x15)
#else
#error Platform not supported by throttling framework.
#endif

#define TH_RTG_EVT_DEFAULT_BUDGET	(1634LLU)	/* 100 MBps */
#define TH_RTG_EVT_MAX_BUDGET		(1634800LLU)	/* 100 GBps */

void th_rtg_create_event(int id, u64 budget);
void th_rtg_update_budget(u64 evt_budget);

#endif /* defined(CONFIG_SCHED_RTGANG) && defined(CONFIG_SCHED_THROTTLE) */

#endif /* __RTG_THROTTLE_H__ */
