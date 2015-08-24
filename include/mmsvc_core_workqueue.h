/**
* Multithreaded work queue.
* Copyright (c) 2012 Ronald Bennett Cemer
* This software is licensed under the BSD license.
* See the accompanying LICENSE.txt for details.
*/

#ifndef __MMSVC_CORE_WORKQUEUE_H__
#define __MMSVC_CORE_WORKQUEUE_H__

#ifdef _cplusplus
extern "C" {
#endif

#include "mmsvc_core_internal.h"
#include "mmsvc_core_log.h"

typedef struct mmsvc_core_workqueue_job {
	gboolean(*job_function) (struct mmsvc_core_workqueue_job * job);
	void *user_data;
	struct mmsvc_core_workqueue_job *prev;
	struct mmsvc_core_workqueue_job *next;
} mmsvc_core_workqueue_job_t;

typedef struct mmsvc_core_workqueue_workqueue {
	struct mmsvc_core_workqueue_worker *workers;
	struct mmsvc_core_workqueue_job *waiting_jobs;
	pthread_mutex_t jobs_mutex;
	pthread_cond_t jobs_cond;
	pthread_t thread;
	void (*shutdown)(void);
	void (*add_job)(mmsvc_core_workqueue_job_t *);
} mmsvc_core_workqueue_workqueue_t;

typedef struct mmsvc_core_workqueue_worker {
	int terminate;
	struct mmsvc_core_workqueue_worker *prev;
	struct mmsvc_core_workqueue_worker *next;
} mmsvc_core_workqueue_worker_t;

mmsvc_core_workqueue_workqueue_t *mmsvc_core_workqueue_get_instance(void);
int mmsvc_core_workqueue_init(int numWorkers);

#ifdef __cplusplus
}
#endif
#endif	/* __MMSVC_CORE_WORKQUEUE_H__ */
