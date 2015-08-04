/**
* Multithreaded work queue.
* Copyright (c) 2012 Ronald Bennett Cemer
* This software is licensed under the BSD license.
* See the accompanying LICENSE.txt for details.
*/

#include "mmsvc_core_workqueue.h"
#define WORK_THREAD_NUM 8
#define LL_ADD(item, list) { \
	item->prev = NULL; \
	item->next = list; \
	list = item; \
}

#define LL_REMOVE(item, list) { \
	if (item->prev != NULL) item->prev->next = item->next; \
	if (item->next != NULL) item->next->prev = item->prev; \
	if (list == item) list = item->next; \
	item->prev = item->next = NULL; \
}

static mmsvc_core_workqueue_workqueue_t *g_workqueue;

static void *_mmsvc_core_workqueue_worker_function(void *ptr);
static void _mmsvc_core_workqueue_shutdown(void);
static void _mmsvc_core_workqueue_add_job(mmsvc_core_workqueue_job_t *job);
static void _mmsvc_core_workqueue_init_instance(void (*shutdown)(void), void (*add_job)(mmsvc_core_workqueue_job_t *));

static void *_mmsvc_core_workqueue_worker_function(void *ptr)
{
	mmsvc_core_workqueue_worker_t *worker = (mmsvc_core_workqueue_worker_t *) ptr;
	mmsvc_core_workqueue_job_t *job;

	while (1) {
		/* Wait until we get notified. */
		pthread_mutex_lock(&worker->workqueue->jobs_mutex);
		while (worker->workqueue->waiting_jobs == NULL) {
			/* If we're supposed to terminate, break out of our continuous loop. */
			if (worker->terminate) {
				LOGD("worker is terminated");
				break;
			}

			pthread_cond_wait(&worker->workqueue->jobs_cond, &worker->workqueue->jobs_mutex);
		}

		/* If we're supposed to terminate, break out of our continuous loop. */
		if (worker->terminate) {
			LOGD("worker is terminated");
			break;
		}

		job = worker->workqueue->waiting_jobs;
		if (job != NULL)
			LL_REMOVE(job, worker->workqueue->waiting_jobs);

		pthread_mutex_unlock(&worker->workqueue->jobs_mutex);

		/* If we didn't get a job, then there's nothing to do at this time. */
		if (job == NULL)
			continue;

		/* Execute the job. */
		job->job_function(job);
	}

	pthread_mutex_unlock(&worker->workqueue->jobs_mutex);
	MMSVC_FREE(worker);

	pthread_exit(NULL);
}

static void _mmsvc_core_workqueue_shutdown(void)
{
	mmsvc_core_workqueue_worker_t *worker = NULL;
	g_return_if_fail(g_workqueue != NULL);
	LOGD("Enter");

	/* Set all workers to terminate. */
	for (worker = g_workqueue->workers; worker != NULL; worker = worker->next) {
		worker->terminate = 1;
	}

	/* Remove all workers and jobs from the work queue.
	 * wake up all workers so that they will terminate. */
	pthread_mutex_lock(&g_workqueue->jobs_mutex);
	g_workqueue->workers = NULL;
	g_workqueue->waiting_jobs = NULL;
	pthread_cond_broadcast(&g_workqueue->jobs_cond);
	pthread_mutex_unlock(&g_workqueue->jobs_mutex);
	LOGD("Leave");
}

static void _mmsvc_core_workqueue_add_job(mmsvc_core_workqueue_job_t *job)
{
	LOGD("Enter");
	/* Add the job to the job queue, and notify a worker. */
	pthread_mutex_lock(&g_workqueue->jobs_mutex);
	LL_ADD(job, g_workqueue->waiting_jobs);
	pthread_cond_signal(&g_workqueue->jobs_cond);
	pthread_mutex_unlock(&g_workqueue->jobs_mutex);
	LOGD("Leave");
}

static void _mmsvc_core_workqueue_init_instance(void (*shutdown)(void), void (*add_job)(mmsvc_core_workqueue_job_t *))
{
	g_return_if_fail(shutdown != NULL);
	g_return_if_fail(add_job != NULL);
	g_return_if_fail(g_workqueue != NULL);

	g_workqueue->shutdown = shutdown;
	g_workqueue->add_job = add_job;
}

mmsvc_core_workqueue_workqueue_t *mmsvc_core_workqueue_get_instance(void)
{
	LOGD("Enter");
	if (g_workqueue == NULL)
		mmsvc_core_workqueue_init(WORK_THREAD_NUM);

	LOGD("Leave");
	return g_workqueue;
}

int mmsvc_core_workqueue_init(int numWorkers)
{
	int i;
	mmsvc_core_workqueue_worker_t *worker;

	pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
	pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;

	g_workqueue = calloc(1, sizeof(mmsvc_core_workqueue_workqueue_t));
	if (!g_workqueue) {
		LOGE("workqueue allocation failed");
		return 1;
	}

	if (numWorkers < 1)
		numWorkers = 1;
	memset(g_workqueue, 0, sizeof(*g_workqueue));
	memcpy(&g_workqueue->jobs_mutex, &blank_mutex, sizeof(g_workqueue->jobs_mutex));
	memcpy(&g_workqueue->jobs_cond, &blank_cond, sizeof(g_workqueue->jobs_cond));

	for (i = 0; i < numWorkers; i++) {
		worker = malloc(sizeof(mmsvc_core_workqueue_worker_t));
		if (worker == NULL) {
			LOGE("Failed to allocate all workers");
			return 1;
		}
		memset(worker, 0, sizeof(*worker));
		worker->workqueue = g_workqueue;
		if (pthread_create(&worker->thread, NULL, _mmsvc_core_workqueue_worker_function, (void *)worker)) {
			LOGE("Failed to start all worker threads");
			MMSVC_FREE(worker);
			return 1;
		}
		LL_ADD(worker, worker->workqueue->workers);
	}

	_mmsvc_core_workqueue_init_instance(_mmsvc_core_workqueue_shutdown, _mmsvc_core_workqueue_add_job);

	return 0;
}