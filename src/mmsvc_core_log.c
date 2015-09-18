/*
 * mmsvc-core
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "mmsvc_core_internal.h"
#include "mmsvc_core_config.h"
#include "mmsvc_core_ipc.h"
#include "mmsvc_core_log.h"
#include "mmsvc_core_workqueue.h"
#ifndef __USE_GNU
#define __USE_GNU /* for gregs */
#endif
#include <ucontext.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define _BUFFER_CACHE 0
#define TUNABLE_CALLER_DEPTH 32
#define U32BITS 0xffffffff
#define READ_DEFAULT_BLOCK_SIZE 1024 * 1024
#define WRITE_DEFAULT_BLOCK_SIZE 4096

static mmsvc_core_log_t *g_mused_log = NULL;

static void _mmsvc_core_log_sig_abort(int signo);
static void _mmsvc_core_log_init_signals(void);
static int _mmsvc_core_log_fd_set_block(int fd);
static void _mmsvc_core_log_sigaction(int signo, siginfo_t *si, void *arg);
static void _mmsvc_core_log_set_log_fd(void);
static void _mmsvc_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean),
	gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int), void (*set_msg) (char *), char * (*get_msg) (void));
static void _mmsvc_core_log_monitor(char *msg);
static void _mmsvc_core_log_fatal(char *msg);
static void _mmsvc_core_log_set_module_value(int index, GModule *module, gboolean value);
static void _mmsvc_core_log_set_msg(char *msg);
static char *_mmsvc_core_log_get_msg(void);
static gboolean _mmsvc_core_log_get_module_opened(int index);
static GModule *_mmsvc_core_log_get_module_value(int index);

static void _mmsvc_core_log_sig_abort(int signo)
{
	if (SIG_ERR == signal(SIGABRT, SIG_DFL))
		LOGE("SIGABRT handler: %s", strerror(errno));

	static char client_name[256];
	memset(client_name, '\0', sizeof(client_name));
	snprintf(client_name, sizeof(client_name) - 1, "[client name] %s", mmsvc_core_config_get_instance()->get_hosts());
	if (write(g_mused_log->log_fd, client_name, strlen(client_name)) != strlen(client_name))
		LOGE("There was an error writing client name to testfile");
	else if (write(g_mused_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", client_name);

	static char client_pid[256];
	memset(client_pid, '\0', sizeof(client_pid));
	snprintf(client_pid, sizeof(client_pid) - 1, "[client pid] %lu", (unsigned long) getpid());
	if (write(g_mused_log->log_fd, client_pid, strlen(client_pid)) != strlen(client_pid))
		LOGE("There was an error writing client pid to testfile");
	else if (write(g_mused_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", client_pid);

	static char latest_called_api[256];
	memset(latest_called_api, '\0', sizeof(latest_called_api));
	snprintf(latest_called_api, sizeof(latest_called_api) - 1, "[client's latest called api] %s", _mmsvc_core_log_get_msg());

	if (write(g_mused_log->log_fd, latest_called_api, strlen(latest_called_api)) != strlen(latest_called_api))
		LOGE("There was an error writing client's latest called api to testfile");
	else if (write(g_mused_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", latest_called_api);

	mmsvc_core_workqueue_get_instance()->shutdown();
	mmsvc_core_ipc_get_instance()->deinit();
	LOGD("abort signal");
	abort();
}

static void _mmsvc_core_log_init_signals(void)
{
	struct sigaction action;

	memset(&action, 0, sizeof(sigaction));
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = _mmsvc_core_log_sigaction;
	action.sa_flags = SA_RESTART | SA_SIGINFO;

	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGABRT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGXCPU, &action, NULL);
}

static int _mmsvc_core_log_fd_set_block(int fd)
{
	int flags;
	int ret;

	flags = fcntl(fd, F_GETFL);
	ret = fcntl(fd, F_SETFL, flags & (U32BITS ^ O_NONBLOCK));

	return ret;
}

static void _mmsvc_core_log_sigaction(int signo, siginfo_t *si, void *arg)
{
	void *trace[TUNABLE_CALLER_DEPTH];
	int tracesize;
	int i;
	char **strings = NULL;
	ucontext_t *uctxt = NULL;

	g_return_if_fail(si != NULL);
	g_return_if_fail(arg != NULL);

	LOGE("----------BEGIN MUSED DYING MESSAGE----------");

	tracesize = backtrace(trace, TUNABLE_CALLER_DEPTH);
	if (tracesize < 0)
		LOGE("backtrace error: %s", strerror(errno));

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
	if (strings == NULL)
		LOGE("backtrace_symbols error: %s", strerror(errno));

	/* skip the first stack frame because it just points here. */
	for (i = 1; i < tracesize; ++i) {
		LOGE("[%u] %s", i - 1, strings[i]);
		if (g_mused_log)
			g_mused_log->fatal(strings[i]);
	}

	LOGE("----------END MUSED DYING MESSAGE----------");

	_mmsvc_core_log_sig_abort(signo);
}

static void _mmsvc_core_log_set_log_fd(void)
{
	g_return_if_fail(g_mused_log != NULL);

	g_mused_log->log_fd = open(LOGFILE, O_CREAT | O_APPEND | O_WRONLY | O_NONBLOCK, 0666);
	if (g_mused_log->log_fd < 0) {
		LOGE("error: %s is not a regular file", LOGFILE);
		return;
	}

	if (fcntl(g_mused_log->log_fd, F_SETFD, FD_CLOEXEC) < 0)
		LOGE("unable to set CLO_EXEC on log fd %d: %s", g_mused_log->log_fd, strerror(errno));

	(void) _mmsvc_core_log_fd_set_block(g_mused_log->log_fd);
}

static void _mmsvc_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean),
	gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int), void (*set_msg) (char *), char * (*get_msg) (void))
{
	g_return_if_fail(log != NULL);
	g_return_if_fail(fatal != NULL);
	g_return_if_fail(g_mused_log == NULL);

	int idx = 0;

	g_mused_log = calloc(1, sizeof(*g_mused_log));
	g_return_if_fail(g_mused_log != NULL);
	g_mused_log->buf = NULL;
	g_mused_log->len = 0;
	g_mused_log->log = log;
	g_mused_log->fatal = fatal;
	g_mused_log->set_module_value = set_module_value;
	g_mused_log->get_module_opened = get_module_opened;
	g_mused_log->get_module_value = get_module_value;
	g_mused_log->timer = g_timer_new();
	g_mused_log->count = 0;
	g_mused_log->set_msg = set_msg;
	g_mused_log->get_msg = get_msg;
	g_timer_stop(g_mused_log->timer);
	for (idx = 0; idx < MMSVC_CLIENT_MAX; idx++) {
		g_mused_log->module_opened[idx] = false;
	}
}

#if _BUFFER_CACHE
size_t
_mmsvc_core_log_saferead(void *buf, size_t count)
{
	size_t nRead = 0;
	while (count > 0) {
		size_t rByte = read(g_mused_log->log_fd, buf, count);
		if (rByte < 0 && errno == EINTR)
			continue;
		if (rByte < 0)
			return rByte;
		if (rByte == 0)
			return nRead;
		buf = (char *)buf + rByte;
		count -= rByte;
		nRead += rByte;
	}
	return nRead;
}

size_t
_mmsvc_core_log_safewrite(const void *buf, size_t count)
{
	size_t nWritten = 0;
	while (count > 0) {
		size_t rByte = write(g_mused_log->log_fd, buf, count);

		if (rByte < 0 && errno == EINTR)
			continue;
		if (rByte < 0)
			return rByte;
		if (rByte == 0)
			return nWritten;
		buf = (const char *)buf + rByte;
		count -= rByte;
		nWritten += rByte;
	}
	return nWritten;
}

static int
_mmsvc_core_log_write_buffer_cache_to_fd(char *msg)
{
	int ret = MM_ERROR_NONE;
	int wbytes = 0;
	int amtread = -1;
	int interval;
	char *zero_buf = NULL;
	char *_buf = NULL;
	struct stat st;

	if (ioctl(g_mused_log->log_fd, BLKBSZGET, &wbytes) < 0)
		wbytes = 0;
	if ((wbytes == 0) && fstat(g_mused_log->log_fd, &st) == 0)
		wbytes = st.st_blksize;
	if (wbytes < WRITE_DEFAULT_BLOCK_SIZE)
		wbytes = WRITE_DEFAULT_BLOCK_SIZE;

	if ((zero_buf = calloc(wbytes, 1)) == NULL) {
		LOGE("Error - zero buf");
		return -errno;
	}

	if ((_buf = calloc(wbytes, 1)) == NULL) {
		LOGE("Error - buf");
		return -errno;
	}

	while (amtread != 0) {
		int amtleft = amtread;
		if ((amtread = _mmsvc_core_log_saferead(_buf, READ_DEFAULT_BLOCK_SIZE)) < 0) {
			LOGE("failed reading from file");
			return -errno;
		}

		do {
			interval = ((wbytes > amtleft) ? amtleft : wbytes);
			int offset = amtread - amtleft;

			if (memcmp(_buf+offset, zero_buf, interval) == 0) {
				if (lseek(g_mused_log->log_fd, interval, SEEK_CUR) < 0) {
					ret = -errno;
					LOGE("cannot extend file %s");
				}
			} else if (_mmsvc_core_log_safewrite(_buf + offset, interval) < 0) {
				LOGE("failed writing to file");
				return -errno;
			}
		} while ((amtleft -= interval) > 0);

		if (fdatasync(g_mused_log->log_fd) < 0) {
			ret = -errno;
			LOGE("cannot sync data to file");
		}
	}

	return ret;
}
#endif
static void _mmsvc_core_log_monitor(char *msg)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(g_mused_log != NULL);

	if (g_mused_log->count != 0)
		g_timer_continue(g_mused_log->timer);

	if (g_mused_log->log_fd < 0) {
		LOGE("Error - log fd");
		return;
	}

	#if _BUFFER_CACHE
	_mmsvc_core_log_write_buffer_cache_to_fd(msg);
	if (_mmsvc_core_log_write_buffer_cache_to_fd(msg) != MM_ERROR_NONE)
		LOGE("There was an error writing to testfile");
	else if (write(g_mused_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", msg);
	#else
	if (write(g_mused_log->log_fd, msg, strlen(msg)) != strlen(msg))
		LOGE("There was an error writing to testfile");
	else if (write(g_mused_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", msg);
	#endif

	if (g_mused_log->count != 0)
		g_timer_stop(g_mused_log->timer);
}

static void _mmsvc_core_log_fatal(char *msg)
{
	if (!msg) {
		LOGE("Error - null msg");
		return;
	}

	_mmsvc_core_log_monitor(msg);
}

static void _mmsvc_core_log_set_module_value(int index, GModule *module, gboolean value)
{
	g_return_if_fail(g_mused_log != NULL);
	g_return_if_fail(module != NULL);

	g_mused_log->module_opened[index] = value;
	g_mused_log->module[index] = module;
	LOGD("module: %p", g_mused_log->module[index]);
}

static void _mmsvc_core_log_set_msg(char *msg)
{
	g_return_if_fail(g_mused_log != NULL);
	g_return_if_fail(msg != NULL);

	g_mused_log->buf = g_strdup(msg);
}

static char *_mmsvc_core_log_get_msg(void)
{
	g_return_if_fail(g_mused_log != NULL);
	g_return_val_if_fail(g_mused_log->buf != NULL, NULL);

	return g_mused_log->buf;
}

static gboolean _mmsvc_core_log_get_module_opened(int index)
{
	g_return_val_if_fail(g_mused_log != NULL, false);

	return g_mused_log->module_opened[index];
}

static GModule *_mmsvc_core_log_get_module_value(int index)
{
	g_return_val_if_fail(g_mused_log != NULL, NULL);

	LOGD("module: %p", g_mused_log->module[index]);
	return g_mused_log->module[index];
}

mmsvc_core_log_t *mmsvc_core_log_get_instance(void)
{
	if (g_mused_log == NULL)
		_mmsvc_core_log_init_instance(_mmsvc_core_log_monitor, _mmsvc_core_log_fatal, _mmsvc_core_log_set_module_value,
		_mmsvc_core_log_get_module_opened, _mmsvc_core_log_get_module_value, _mmsvc_core_log_set_msg, _mmsvc_core_log_get_msg);

	return g_mused_log;
}

void mmsvc_core_log_init(void)
{
	LOGD("Enter");

	if (g_mused_log == NULL)
		_mmsvc_core_log_init_instance(_mmsvc_core_log_monitor, _mmsvc_core_log_fatal, _mmsvc_core_log_set_module_value,
		_mmsvc_core_log_get_module_opened, _mmsvc_core_log_get_module_value, _mmsvc_core_log_set_msg, _mmsvc_core_log_get_msg);

	_mmsvc_core_log_set_log_fd();
	_mmsvc_core_log_init_signals();

	LOGD("Leave");
}
