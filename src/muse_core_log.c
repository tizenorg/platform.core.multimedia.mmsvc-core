/*
 * muse-core
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

#include "muse_core_internal.h"
#include "muse_core_config.h"
#include "muse_core_ipc.h"
#include "muse_core_log.h"
#include "muse_core_workqueue.h"
#ifndef __USE_GNU
#define __USE_GNU /* for gregs */
#endif
#include <ucontext.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#define TUNABLE_CALLER_DEPTH 32
#define U32BITS 0xffffffff
#define READ_DEFAULT_BLOCK_SIZE 1024 * 1024
#define WRITE_DEFAULT_BLOCK_SIZE 4096

static muse_core_log_t *g_muse_core_log = NULL;

static void _muse_core_log_sig_abort(int signo);
static void _muse_core_log_init_signals(void);
static int _muse_core_log_fd_set_block(int fd);
static void _muse_core_log_sigaction(int signo, siginfo_t *si, void *arg);
static void _muse_core_log_set_log_fd(void);
static void _muse_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean),
	gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int), void (*set_msg) (char *), char * (*get_msg) (void));
static void _muse_core_log_monitor(char *msg);
static void _muse_core_log_fatal(char *msg);
static void _muse_core_log_set_module_value(int index, GModule *module, gboolean value);
static void _muse_core_log_set_msg(char *msg);
static char *_muse_core_log_get_msg(void);
static gboolean _muse_core_log_get_module_opened(int index);
static GModule *_muse_core_log_get_module_value(int index);

static void _muse_core_log_sig_abort(int signo)
{
	if (SIG_ERR == signal(SIGABRT, SIG_DFL))
		LOGE("SIGABRT handler: %s", strerror(errno));

	static char client_name[256];
	memset(client_name, '\0', sizeof(client_name));
	snprintf(client_name, sizeof(client_name) - 1, "[client name] %s", muse_core_config_get_instance()->get_hosts());
	if (write(g_muse_core_log->log_fd, client_name, strlen(client_name)) != strlen(client_name))
		LOGE("There was an error writing client name to testfile");
	else if (write(g_muse_core_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", client_name);

	static char client_pid[256];
	memset(client_pid, '\0', sizeof(client_pid));
	snprintf(client_pid, sizeof(client_pid) - 1, "[client pid] %lu", (unsigned long) getpid());
	if (write(g_muse_core_log->log_fd, client_pid, strlen(client_pid)) != strlen(client_pid))
		LOGE("There was an error writing client pid to testfile");
	else if (write(g_muse_core_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", client_pid);

	static char latest_called_api[256];
	memset(latest_called_api, '\0', sizeof(latest_called_api));
	snprintf(latest_called_api, sizeof(latest_called_api) - 1, "[client's latest called api] %s", _muse_core_log_get_msg());

	if (write(g_muse_core_log->log_fd, latest_called_api, strlen(latest_called_api)) != strlen(latest_called_api))
		LOGE("There was an error writing client's latest called api to testfile");
	else if (write(g_muse_core_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", latest_called_api);

	muse_core_workqueue_get_instance()->shutdown();
	muse_core_ipc_get_instance()->deinit();
	LOGD("abort signal");
	abort();
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

	g_return_if_fail(si != NULL);
	g_return_if_fail(arg != NULL);

	LOGE("----------BEGIN MUSE DYING MESSAGE----------");

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
	if (strings == NULL) {
		LOGE("backtrace_symbols error: %s", strerror(errno));
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

static void _muse_core_log_set_log_fd(void)
{
	g_return_if_fail(g_muse_core_log != NULL);

	g_muse_core_log->log_fd = open(LOGFILE, O_CREAT | O_APPEND | O_WRONLY | O_NONBLOCK, 0666);
	if (g_muse_core_log->log_fd < 0) {
		LOGE("error: %s is not a regular file", LOGFILE);
		return;
	}

	if (fcntl(g_muse_core_log->log_fd, F_SETFD, FD_CLOEXEC) < 0)
		LOGE("unable to set CLO_EXEC on log fd %d: %s", g_muse_core_log->log_fd, strerror(errno));

	(void) _muse_core_log_fd_set_block(g_muse_core_log->log_fd);
}

static void _muse_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean),
	gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int), void (*set_msg) (char *), char * (*get_msg) (void))
{
	g_return_if_fail(log != NULL);
	g_return_if_fail(fatal != NULL);
	g_return_if_fail(g_muse_core_log == NULL);

	int idx = 0;

	g_muse_core_log = calloc(1, sizeof(*g_muse_core_log));
	g_return_if_fail(g_muse_core_log != NULL);
	g_muse_core_log->buf = NULL;
	g_muse_core_log->len = 0;
	g_muse_core_log->log = log;
	g_muse_core_log->fatal = fatal;
	g_muse_core_log->set_module_value = set_module_value;
	g_muse_core_log->get_module_opened = get_module_opened;
	g_muse_core_log->get_module_value = get_module_value;
	g_muse_core_log->timer = g_timer_new();
	g_muse_core_log->count = 0;
	g_muse_core_log->set_msg = set_msg;
	g_muse_core_log->get_msg = get_msg;
	g_timer_stop(g_muse_core_log->timer);
	for (idx = 0; idx < MUSE_MODULE_MAX; idx++) {
		g_muse_core_log->module_opened[idx] = false;
	}
}

static size_t _muse_core_log_safewrite(const void *buf, size_t count)
{
	size_t nWritten = 0;
	while (count > 0) {
		size_t rByte = write(g_muse_core_log->log_fd, buf, count);

		if (rByte < 0 && errno == EINTR)
			continue;
		if (rByte == 0)
			return nWritten;
		buf = (const char *)buf + rByte;
		count -= rByte;
		nWritten += rByte;
	}
	return nWritten;
}

static int _muse_core_log_write_buffer_cache_to_fd(char *msg)
{
	int ret = MM_ERROR_NONE;
	int written = 0;
	off_t remaining = 0;
	size_t write_size = 0;
	size_t bytes_wiped = 0;
	size_t writebuf_length = 0;
	struct stat st;

	if (ioctl(g_muse_core_log->log_fd, BLKBSZGET, &writebuf_length) < 0)
		writebuf_length = 0;

	if ((writebuf_length == 0) && fstat(g_muse_core_log->log_fd, &st) == 0)
		writebuf_length = st.st_blksize;

	if (writebuf_length < WRITE_DEFAULT_BLOCK_SIZE)
		writebuf_length = WRITE_DEFAULT_BLOCK_SIZE;

	if ((ret = lseek(g_muse_core_log->log_fd, writebuf_length, SEEK_SET)) < 0) {
		LOGE("Failed to seek to position");
		return ret;
	}

	remaining = WRITE_DEFAULT_BLOCK_SIZE;
	while (remaining > 0) {
		write_size = (writebuf_length < remaining) ? writebuf_length : remaining;
		written = _muse_core_log_safewrite(msg, write_size);
		if (written < 0) {
			LOGE("Failed to write %zu bytes to storage volume with path", write_size);
			return ret;
		}
		bytes_wiped += written;
		remaining -= written;
	}

	if (fdatasync(g_muse_core_log->log_fd) < 0) {
		ret = -errno;
		LOGE("cannot sync data to volume with path");
		return ret;
	}

	return MM_ERROR_NONE;
}

static void _muse_core_log_monitor(char *msg)
{
	g_return_if_fail(msg != NULL);
	g_return_if_fail(g_muse_core_log != NULL);

	if (g_muse_core_log->count != 0)
		g_timer_continue(g_muse_core_log->timer);

	if (g_muse_core_log->log_fd < 0) {
		LOGE("Error - log fd");
		return;
	}

	_muse_core_log_write_buffer_cache_to_fd(msg);
	if (_muse_core_log_write_buffer_cache_to_fd(msg) != MM_ERROR_NONE)
		LOGE("There was an error writing to testfile");
	else if (write(g_muse_core_log->log_fd, "\n", 1) != 1)
		LOGE("write %s", msg);

	if (g_muse_core_log->count != 0)
		g_timer_stop(g_muse_core_log->timer);
}

static void _muse_core_log_fatal(char *msg)
{
	if (!msg) {
		LOGE("Error - null msg");
		return;
	}

	_muse_core_log_monitor(msg);
}

static void _muse_core_log_set_module_value(int index, GModule *module, gboolean value)
{
	g_return_if_fail(g_muse_core_log != NULL);
	g_return_if_fail(module != NULL);

	g_muse_core_log->module_opened[index] = value;
	g_muse_core_log->module[index] = module;
	LOGD("module: %p", g_muse_core_log->module[index]);
}

static void _muse_core_log_set_msg(char *msg)
{
	g_return_if_fail(g_muse_core_log != NULL);
	g_return_if_fail(msg != NULL);

	g_muse_core_log->buf = g_strdup(msg);
}

static char *_muse_core_log_get_msg(void)
{
	g_return_val_if_fail(g_muse_core_log != NULL, NULL);
	g_return_val_if_fail(g_muse_core_log->buf != NULL, NULL);

	return g_muse_core_log->buf;
}

static gboolean _muse_core_log_get_module_opened(int index)
{
	g_return_val_if_fail(g_muse_core_log != NULL, false);

	return g_muse_core_log->module_opened[index];
}

static GModule *_muse_core_log_get_module_value(int index)
{
	g_return_val_if_fail(g_muse_core_log != NULL, NULL);

	LOGD("module: %p", g_muse_core_log->module[index]);
	return g_muse_core_log->module[index];
}

muse_core_log_t *muse_core_log_get_instance(void)
{
	if (g_muse_core_log == NULL)
		_muse_core_log_init_instance(_muse_core_log_monitor, _muse_core_log_fatal, _muse_core_log_set_module_value,
		_muse_core_log_get_module_opened, _muse_core_log_get_module_value, _muse_core_log_set_msg, _muse_core_log_get_msg);

	return g_muse_core_log;
}

void muse_core_log_init(void)
{
	LOGD("Enter");

	if (g_muse_core_log == NULL)
		_muse_core_log_init_instance(_muse_core_log_monitor, _muse_core_log_fatal, _muse_core_log_set_module_value,
		_muse_core_log_get_module_opened, _muse_core_log_get_module_value, _muse_core_log_set_msg, _muse_core_log_get_msg);

	_muse_core_log_set_log_fd();
	_muse_core_log_init_signals();

	LOGD("Leave");
}
