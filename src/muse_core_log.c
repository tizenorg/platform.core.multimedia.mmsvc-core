/*
 * muse-core
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: YoungHun Kim <yh8004.kim@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "muse_core_internal.h"
#include "muse_core_config.h"
#include "muse_core_ipc.h"
#include "muse_core_log.h"
#include "muse_core_workqueue.h"
#include "muse_core_security.h"
#ifndef __USE_GNU
#define __USE_GNU /* for gregs */
#endif
#include <ucontext.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#define TUNABLE_CALLER_DEPTH 32
#define U32BITS 0xffffffff
#define MAX_FILE_NUM 3
#define MAX_SIZE 33554432
#define WRITE_FAIL -1

static muse_core_log_t *g_muse_core_log = NULL;

static void _muse_core_log_sig_abort(int signo);
static void _muse_core_log_init_signals(void);
static int _muse_core_log_fd_set_block(int fd);
static void _muse_core_log_sigaction(int signo, siginfo_t *si, void *arg);
static void _muse_core_log_set_log_fd(void);
static void _muse_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_msg) (char *),
						char * (*get_msg) (void), void (*flush_msg) (void), void (*free) (void));
static void _muse_core_log_write_buffer(const void *buf, size_t len);
static void _muse_core_log_monitor(char *msg);
static void _muse_core_log_fatal(char *msg);
static void _muse_core_log_set_msg(char *msg);
static char *_muse_core_log_get_msg(void);
static void _muse_core_log_flush_msg(void);
static void _muse_core_log_free(void);

static void _muse_core_log_sig_abort(int signo)
{
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};
	if (SIG_ERR == signal(SIGABRT, SIG_DFL)) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("SIGABRT handler: %s", err_msg);
	}

	if (g_muse_core_log) {
		static char client_buf[256];
		snprintf(client_buf, sizeof(client_buf), "[client name] %s", muse_core_config_get_instance()->get_host(muse_core_module_get_instance()->api_module));
		if (write(g_muse_core_log->log_fd, client_buf, strlen(client_buf)) == WRITE_FAIL)
			LOGE("There was an error writing client name to logfile");
		else if (write(g_muse_core_log->log_fd, "\n", 1) != WRITE_FAIL)
			LOGE("write %s", client_buf);

		snprintf(client_buf, sizeof(client_buf), "[client pid] %lu", (unsigned long) getpid());
		if (write(g_muse_core_log->log_fd, client_buf, strlen(client_buf)) == WRITE_FAIL)
			LOGE("There was an error writing client pid to logfile");
		else if (write(g_muse_core_log->log_fd, "\n", 1) == WRITE_FAIL)
			LOGE("write %s", client_buf);

		snprintf(client_buf, sizeof(client_buf), "[client's latest called api] %s", _muse_core_log_get_msg());
		if (write(g_muse_core_log->log_fd, client_buf, strlen(client_buf)) == WRITE_FAIL)
			LOGE("There was an error writing client's latest called api to logfile");
		else if (write(g_muse_core_log->log_fd, "\n", 1) == WRITE_FAIL)
			LOGE("write %s", client_buf);
	}

	LOGD("signo(%d)", signo);
	if (signo == SIGABRT || signo == SIGSEGV)
		abort();
	else
		raise(signo);
}

static void _muse_core_log_init_signals(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(sigaction));
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = _muse_core_log_sigaction;
	action.sa_flags = SA_RESTART | SA_SIGINFO;

	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGXCPU, &action, NULL);
}

static int _muse_core_log_fd_set_block(int fd)
{
	int flags;
	int ret;

	flags = fcntl(fd, F_GETFL);
	ret = fcntl(fd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

	return ret;
}

static void _muse_core_log_sigaction(int signo, siginfo_t *si, void *arg)
{
	void *trace[TUNABLE_CALLER_DEPTH];
	int tracesize;
	int i;
	char **strings = NULL;
	ucontext_t *uctxt = NULL;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	g_return_if_fail(si != NULL);
	g_return_if_fail(arg != NULL);

	LOGE("----------BEGIN MUSE DYING MESSAGE----------");

	tracesize = backtrace(trace, TUNABLE_CALLER_DEPTH);
	if (tracesize < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("backtrace error: %s", err_msg);
	}

	uctxt = (ucontext_t *) arg;

	if (!uctxt) {
		LOGE("Error - null uctxt");
		return;
	}

	#if defined(REG_EIP) /*eip is the instruction pointer register, which contains the address of the location immediately following the current instruction in 32bit mode*/
	trace[1] = (void *) uctxt->uc_mcontext.gregs[REG_EIP];
	#elif defined(REG_RIP) /* rip is the instruction pointer register, which contains the address of the location immediately following the current instruction in 64bit mode*/
	trace[1] = (void *) uctxt->uc_mcontext.gregs[REG_RIP];
	#endif
	strings = backtrace_symbols(trace, tracesize);
	if (strings == NULL) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("backtrace_symbols error: %s", err_msg);
	} else {
		/* skip the first stack frame because it just points here. */
		for (i = 1; i < tracesize; ++i) {
			LOGE("[%u] %s", i - 1, strings[i]);
			if (g_muse_core_log)
				g_muse_core_log->fatal(strings[i]);
		}
	}

	LOGE("----------END MUSE DYING MESSAGE----------");

	_muse_core_log_sig_abort(signo);
}

static int _muse_core_log_open_work(const char *path)
{
	return open(path, O_CREAT | O_APPEND | O_WRONLY | O_NONBLOCK, 0666);
}

static void _muse_core_log_create_fd(void)
{
	int selected_index, index;
	struct stat st;
	char file[MAX_FILE_NUM][TUNABLE_CALLER_DEPTH];

	for (index = 0; index < MAX_FILE_NUM; index++)
		snprintf(file[index], strlen(LOGFILE) + 3, "%s.%d", LOGFILE, index);

	for (index = 0; index < MAX_FILE_NUM; index++) {
		if (access(file[index], F_OK ) == 0) { /* if 0, then there is file */
			stat(file[index], &st);
			g_muse_core_log->size = st.st_size;
			if (g_muse_core_log->size > MAX_SIZE) {
				selected_index = (index + 1) % MAX_FILE_NUM;
				break;
			} else {
				selected_index = index;
				break;
			}
		} else {
			selected_index = index;
			break;
		}
	}

	LOGD("filename: %s", file[selected_index]);
	/* open log file again */
	g_muse_core_log->log_fd = _muse_core_log_open_work(file[selected_index]);
	if (g_muse_core_log->log_fd < 0) {
		LOGE("couldn't open log file");
		exit(EXIT_FAILURE);
	}

	return;
}

static void _muse_core_log_set_log_fd(void)
{
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};
	g_return_if_fail(g_muse_core_log != NULL);

	_muse_core_log_create_fd();

	if (fcntl(g_muse_core_log->log_fd, F_SETFD, FD_CLOEXEC) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("unable to set CLO_EXEC on log fd %d: %s", g_muse_core_log->log_fd, err_msg);
	}

	(void) _muse_core_log_fd_set_block(g_muse_core_log->log_fd);
}

static void _muse_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_msg) (char *),
						char * (*get_msg) (void), void (*flush_msg) (void), void (*free) (void))
{
	g_return_if_fail(log != NULL);
	g_return_if_fail(fatal != NULL);
	g_return_if_fail(g_muse_core_log == NULL);

	g_muse_core_log = calloc(1, sizeof(*g_muse_core_log));
	g_return_if_fail(g_muse_core_log != NULL);
	g_muse_core_log->buf = NULL;
	g_muse_core_log->size = 0;
	memset(g_muse_core_log->cache, 0, MUSE_MSG_MAX_LENGTH);
	g_muse_core_log->log = log;
	g_muse_core_log->fatal = fatal;
	g_muse_core_log->count = 0;
	g_muse_core_log->set_msg = set_msg;
	g_muse_core_log->get_msg = get_msg;
	g_muse_core_log->flush_msg = flush_msg;
	g_muse_core_log->free = free;
}

static void
_muse_core_log_write_buffer(const void *buf, size_t len)
{
	g_return_if_fail(buf != NULL);
	memcpy(g_muse_core_log->cache + strlen(g_muse_core_log->cache), buf, len);
	memcpy(g_muse_core_log->cache + strlen(g_muse_core_log->cache), "\n", 1);
}

static void _muse_core_log_monitor(char *msg)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(g_muse_core_log != NULL);

	if (g_muse_core_log->log_fd < 0) {
		LOGE("Error - log fd");
		return;
	}

	if (strlen(g_muse_core_log->cache) + strlen(msg) < MUSE_MSG_MAX_LENGTH) {
		_muse_core_log_write_buffer(msg, strlen(msg));
	} else {
		if (write(g_muse_core_log->log_fd, g_muse_core_log->cache, strlen(g_muse_core_log->cache)) != WRITE_FAIL) {
			memset(g_muse_core_log->cache, 0, MUSE_MSG_MAX_LENGTH);
			_muse_core_log_write_buffer(msg, strlen(msg));
		} else {
			LOGE("There was an error writing to logfile");
		}
	}
}

static void _muse_core_log_fatal(char *msg)
{
	if (!msg) {
		LOGE("Error - null msg");
		return;
	}

	_muse_core_log_monitor(msg);
}

static void _muse_core_log_free(void)
{
	LOGD("Enter");

	MUSE_FREE(g_muse_core_log);

	LOGD("Leave");
}

static void _muse_core_log_set_msg(char *msg)
{
	g_return_if_fail(g_muse_core_log != NULL);
	g_return_if_fail(msg != NULL);

	g_muse_core_log->buf = msg;
}

static char *_muse_core_log_get_msg(void)
{
	g_return_val_if_fail(g_muse_core_log != NULL, NULL);
	g_return_val_if_fail(g_muse_core_log->buf != NULL, NULL);

	return g_muse_core_log->buf;
}

static void _muse_core_log_flush_msg(void)
{
	if (write(g_muse_core_log->log_fd, g_muse_core_log->cache, strlen(g_muse_core_log->cache)) != (int)strlen(g_muse_core_log->cache))
		LOGE("There was an error writing to logfile");
}

muse_core_log_t *muse_core_log_get_instance(void)
{
	if (g_muse_core_log == NULL)
		_muse_core_log_init_instance(_muse_core_log_monitor, _muse_core_log_fatal, _muse_core_log_set_msg,
								_muse_core_log_get_msg, _muse_core_log_flush_msg, _muse_core_log_free);

	return g_muse_core_log;
}

void muse_core_log_init(void)
{
	LOGD("Enter");

	if (g_muse_core_log == NULL)
		_muse_core_log_init_instance(_muse_core_log_monitor, _muse_core_log_fatal, _muse_core_log_set_msg,
								_muse_core_log_get_msg, _muse_core_log_flush_msg, _muse_core_log_free);

	_muse_core_log_set_log_fd();
	_muse_core_log_init_signals();

	LOGD("Leave");
}
