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
#include "mmsvc_core_log.h"
#include <ucontext.h>

/* Signals */
#define RECEIVED_SIG_RESTART    0x0001
#define RECEIVED_SIG_EXIT       0x0002
#define RECEIVED_SIG_SHUTDOWN   0x0004
#define RECEIVED_SIG_SEGV       0x0008
#define RECEIVED_SIG_TERMINATE  0x0010
#define RECEIVED_SIG_XCPU       0x0020
#define RECEIVED_SIG_TERM_OTHER 0x0040
#define RECEIVED_SIG_ABORT      0x0080
#define RECEIVED_SIG_EVENT      0x0100
#define RECEIVED_SIG_CHLD       0x0200
#define RECEIVED_SIG_ALRM       0x0400
#define TUNABLE_CALLER_DEPTH 32
#define MSG_LENGTH 1024 * 1024
#define U32BITS 0xffffffff
#define FILESYSTEMIO_MAX_DUPFDS 512

static mmsvc_core_log_t *g_mused_log = NULL;
volatile unsigned int received_signal_flags = 0;

static void _mmsvc_core_log_sig_child(int signo);
static char *_mmsvc_core_log_prepare_core(void);
static void _mmsvc_core_log_sig_abort(int signo);
static void _mmsvc_core_log_sig_terminate(int signo);
static void _mmsvc_core_log_sig_restart(int signo);
static int _mmsvc_core_log_init_signal_set(void);
static void _mmsvc_core_log_init_signals(void);
static int _mmsvc_core_log_fd_set_block(int fd);
static void _mmsvc_core_log_sigaction(int signo, siginfo_t *si, void *arg);
static void _mmsvc_core_log_set_log_fd(void);
static void _mmsvc_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean), gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int));
static void _mmsvc_core_log_monitor(char *msg);
static void _mmsvc_core_log_fatal(char *msg);
static int _mmsvc_core_log_init_signal_set(void);
static void _mmsvc_core_log_set_module_value(int index, GModule *module, gboolean value);
static gboolean _mmsvc_core_log_get_module_opened(int index);
static GModule *_mmsvc_core_log_get_module_value(int index);

static void _mmsvc_core_log_sig_child(int signo)
{
	received_signal_flags |= RECEIVED_SIG_CHLD;

	if (SIG_ERR == signal(SIGCHLD, _mmsvc_core_log_sig_child))
		LOGE("SIGCHLD handler: %s", strerror(errno));
}

static char *_mmsvc_core_log_prepare_core(void)
{
	int result = chdir("/");
	static char dir[256];

	memset(dir, '\0', sizeof(dir));
	snprintf(dir, sizeof(dir)-1, "%s/mused_%lu", MUSED_DIR, (unsigned long) getpid());

	if (mkdir(dir, 0700) < 0) {
		LOGE("unable to create directory '%s' for coredump: %s", dir, strerror(errno));
	} else {
		result = chdir(dir);
		LOGD("result = %d", result);
	}

	return dir;
}

static void _mmsvc_core_log_sig_abort(int signo)
{
	received_signal_flags |= RECEIVED_SIG_ABORT;

	if (SIG_ERR == signal(SIGABRT, SIG_DFL))
		LOGE("SIGABRT andler: %s", strerror(errno));

	LOGD("mused received SIGABRT signal, generating core file in %s", _mmsvc_core_log_prepare_core());
	abort();
}

static void _mmsvc_core_log_sig_terminate(int signo)
{
	if (signo == SIGSEGV || signo == SIGXCPU || signo == SIGBUS) {
		if (signo == SIGXCPU) {
			received_signal_flags |= RECEIVED_SIG_XCPU;
		} else {
			received_signal_flags |= RECEIVED_SIG_SEGV;
		}

		LOGD("mused terminating (%d)", signo);

	} else if (signo == SIGTERM) {
		received_signal_flags |= RECEIVED_SIG_TERMINATE;

	} else {
		received_signal_flags |= RECEIVED_SIG_TERM_OTHER;
	}

	if (SIG_ERR == signal(signo, SIG_IGN))
		LOGE("handler for %d: %s", signo, strerror(errno));
}

static void _mmsvc_core_log_sig_restart(int signo)
{
	received_signal_flags |= RECEIVED_SIG_RESTART;

	if (SIG_ERR == signal(SIGHUP, _mmsvc_core_log_sig_restart))
		LOGE("SIGHUP andler: %s", strerror(errno));
}

static void _mmsvc_core_log_signals_handle_event(int signo)
{
	received_signal_flags |= RECEIVED_SIG_EVENT;

	if (SIG_ERR == signal(SIGUSR2, _mmsvc_core_log_signals_handle_event))
		LOGE(" SIGUSR2 handler: %s", strerror(errno));
}

static int _mmsvc_core_log_init_signal_set(void)
{
	sigset_t mmsvc_core_log_sig_set;

	sigemptyset(&mmsvc_core_log_sig_set);

	sigaddset(&mmsvc_core_log_sig_set, SIGCHLD);
	sigaddset(&mmsvc_core_log_sig_set, SIGINT);
	sigaddset(&mmsvc_core_log_sig_set, SIGQUIT);
	sigaddset(&mmsvc_core_log_sig_set, SIGILL);
	sigaddset(&mmsvc_core_log_sig_set, SIGABRT);
	sigaddset(&mmsvc_core_log_sig_set, SIGFPE);
	sigaddset(&mmsvc_core_log_sig_set, SIGSEGV);
	sigaddset(&mmsvc_core_log_sig_set, SIGALRM);
	sigaddset(&mmsvc_core_log_sig_set, SIGTERM);
	sigaddset(&mmsvc_core_log_sig_set, SIGHUP);
	sigaddset(&mmsvc_core_log_sig_set, SIGUSR2);
	sigaddset(&mmsvc_core_log_sig_set, SIGSTKFLT);
	sigaddset(&mmsvc_core_log_sig_set, SIGIO);
	sigaddset(&mmsvc_core_log_sig_set, SIGBUS);

	if (SIG_ERR == signal(SIGCHLD, _mmsvc_core_log_sig_child) || SIG_ERR == signal(SIGHUP, _mmsvc_core_log_sig_restart)
		|| SIG_ERR == signal(SIGINT, _mmsvc_core_log_sig_terminate) || SIG_ERR == signal(SIGQUIT, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGILL, _mmsvc_core_log_sig_terminate) || SIG_ERR == signal(SIGFPE, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGABRT, _mmsvc_core_log_sig_abort) 	|| SIG_ERR == signal(SIGSEGV, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGXCPU, _mmsvc_core_log_sig_terminate) || SIG_ERR == signal(SIGBUS, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGALRM, SIG_IGN) || SIG_ERR == signal(SIGTERM, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGURG, SIG_IGN) || SIG_ERR == signal(SIGSTKFLT, _mmsvc_core_log_sig_terminate)
		|| SIG_ERR == signal(SIGIO, SIG_IGN) || SIG_ERR == signal(SIGUSR2, _mmsvc_core_log_signals_handle_event)
		|| 0 > sigprocmask(SIG_UNBLOCK, &mmsvc_core_log_sig_set, NULL)) {
			LOGE("signal : %s", strerror(errno));
		}

	return 0;
}

static void _mmsvc_core_log_init_signals(void)
{
	struct sigaction action;

	_mmsvc_core_log_init_signal_set();

	memset(&action, 0, sizeof(sigaction));
	sigemptyset(&action.sa_mask);
	action.sa_sigaction = _mmsvc_core_log_sigaction;
	action.sa_flags = SA_RESTART | SA_SIGINFO;

	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	sigaction(SIGXCPU, &action, NULL);
	sigaction(SIGUSR1, &action, NULL);
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

	g_return_if_fail(si != NULL);
	g_return_if_fail(arg != NULL);

	_mmsvc_core_log_sig_terminate(signo);

	LOGE("----------BEGIN MUSED DYING MESSAGE----------");

	tracesize = backtrace(trace, TUNABLE_CALLER_DEPTH);
	if (tracesize < 0)
		LOGE("backtrace error: %s", strerror(errno));

	#if defined(REG_EIP)
	int i;
	char **strings = NULL;
	/* overwrite sigaction with caller's address for x86*/
	ucontext_t *uctxt = NULL;
	uctxt = (ucontext_t *) arg;

	if (!uctxt) {
		LOGE("Error - null uctxt");
		return;
	}

	trace[1] = (void *) uctxt->uc_mcontext.gregs[REG_EIP];
	strings = backtrace_symbols(trace, tracesize);
	if (strings == NULL)
		LOGE("backtrace_symbols error: %s", strerror(errno));

	/* skip the first stack frame because it just points here. */
	for (i = 1; i < tracesize; ++i) {
		LOGE("[%u] %s", i-1, strings[i]);
		if (g_mused_log)
			g_mused_log->fatal(strings[i]);
	}
	#endif

	LOGE("----------END MUSED DYING MESSAGE----------");

	LOGE("exit(0) - caught segfault at address %p", si->si_addr);

	exit(0);
}

static void _mmsvc_core_log_set_log_fd(void)
{
	LOGD("Enter");

	g_return_if_fail(g_mused_log != NULL);

	g_mused_log->log_fd = open(LOGFILE, O_CREAT | O_APPEND | O_WRONLY | O_NONBLOCK, 0666);
	if (g_mused_log->log_fd < 0) {
		LOGE("error: %s is not a regular file", LOGFILE);
		return;
	}

	if (fcntl(g_mused_log->log_fd, F_SETFD, FD_CLOEXEC) < 0)
		LOGE("unable to set CLO_EXEC on log fd %d: %s", g_mused_log->log_fd, strerror(errno));

	(void) _mmsvc_core_log_fd_set_block(g_mused_log->log_fd);

	LOGD("Leave");
}

static void _mmsvc_core_log_init_instance(void (*log)(char *), void (*fatal)(char *), void (*set_module_value) (int, GModule *, gboolean), gboolean(*get_module_opened) (int), GModule * (*get_module_value) (int))
{
	g_return_if_fail(log != NULL);
	g_return_if_fail(fatal != NULL);
	g_return_if_fail(g_mused_log == NULL);

	int idx = 0;

	g_mused_log = calloc(1, sizeof(*g_mused_log));
	g_mused_log->buf = NULL;
	g_mused_log->len = 0;
	g_mused_log->log = log;
	g_mused_log->fatal = fatal;
	g_mused_log->set_module_value = set_module_value;
	g_mused_log->get_module_opened = get_module_opened;
	g_mused_log->get_module_value = get_module_value;
	g_mused_log->timer = g_timer_new();
	g_mused_log->count = 0;
	g_timer_stop(g_mused_log->timer);
	for (idx = 0; idx < MMSVC_CLIENT_MAX; idx++) {
		g_mused_log->module_opened[idx] = false;
	}
}

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

	if (write(g_mused_log->log_fd, msg, strlen(msg)) != strlen(msg)) {
		LOGE("There was an error writing to testfile");
	} else {
		if (write(g_mused_log->log_fd, "\n", 1) == 1)
			LOGD("write %s", msg);
	}

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

	exit(-1);
}

static void _mmsvc_core_log_set_module_value(int index, GModule *module, gboolean value)
{
	g_return_if_fail(g_mused_log != NULL);
	g_return_if_fail(module != NULL);

	g_mused_log->module_opened[index] = value;
	g_mused_log->module[index] = module;
	LOGD("module: %p", g_mused_log->module[index]);
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
		_mmsvc_core_log_get_module_opened, _mmsvc_core_log_get_module_value);

	return g_mused_log;
}

void mmsvc_core_log_init(void)
{
	LOGD("Enter");

	if (g_mused_log == NULL)
		_mmsvc_core_log_init_instance(_mmsvc_core_log_monitor, _mmsvc_core_log_fatal, _mmsvc_core_log_set_module_value,
		_mmsvc_core_log_get_module_opened, _mmsvc_core_log_get_module_value);

	_mmsvc_core_log_set_log_fd();
	_mmsvc_core_log_init_signals();

	LOGD("Leave");
}
