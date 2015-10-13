/**
* Multithreaded work queue.
* Copyright (c) 2012 Ronald Bennett Cemer
* This software is licensed under the BSD license.
* See the accompanying LICENSE.txt for details.
*/

#ifndef __MUSE_CORE_WORKQUEUE_H__
#define __MUSE_CORE_WORKQUEUE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "muse_core_internal.h"
#include "muse_core_log.h"

#define MUSE_WORK_THREAD_NUM 8

typedef struct muse_core_workqueue_job {
	gboolean(*job_function) (struct muse_core_workqueue_job * job);
	void *user_data;
	struct muse_core_workqueue_job *prev;
	struct muse_core_workqueue_job *next;
} muse_core_workqueue_job_t;

typedef struct muse_core_workqueue_workqueue {
	struct muse_core_workqueue_worker *workers;
	struct muse_core_workqueue_job *waiting_jobs;
	pthread_mutex_t jobs_mutex;
	pthread_cond_t jobs_cond;
	void (*shutdown)(void);
	void (*add_job)(muse_core_workqueue_job_t *);
} muse_core_workqueue_workqueue_t;

typedef struct muse_core_workqueue_worker {
	pthread_t thread;
	int terminate;
	struct muse_core_workqueue_workqueue *workqueue;
	struct muse_core_workqueue_worker *prev;
	struct muse_core_workqueue_worker *next;
} muse_core_workqueue_worker_t;

muse_core_workqueue_workqueue_t *muse_core_workqueue_get_instance(void);
int muse_core_workqueue_init(int numWorkers);

#ifdef __cplusplus
}
#endif
#endif	/* __MUSE_CORE_WORKQUEUE_H__ */
