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

#include "mmsvc_core.h"
#include "mmsvc_core_private.h"
#include "mmsvc_core_config.h"
#include "mmsvc_core_internal.h"
#include "mmsvc_core_ipc.h"
#include "mmsvc_core_log.h"
#include "mmsvc_core_workqueue.h"

#define FILENAMELEN 32
#define WORK_THREAD_NUM 8
#define LOG_SLEEP_TIMER 10

static MMServer *server;
static GMainLoop *g_loop;
static GThread *g_thread;
static char *UDS_files[MUSED_CHANNEL_MAX] = {SOCKFILE0, SOCKFILE1};

static gboolean (*job_functions[MUSED_CHANNEL_MAX])
	(mmsvc_core_workqueue_job_t *job) = {
		mmsvc_core_ipc_job_function,
		mmsvc_core_ipc_data_job_function
	};

static int _mmsvc_core_set_nonblocking(int fd);
static int _mmsvc_core_check_server_is_running(void);
static MMServer *_mmsvc_core_create_new_server_from_fd(int fd[], int type);
static gboolean _mmsvc_core_connection_handler(GIOChannel *source,
		GIOCondition condition, gpointer data);
static int _mmsvc_core_free(MMServer *server);

static int _mmsvc_core_set_nonblocking(int fd)
{
	int flags = fcntl(fd, F_GETFL, NULL);

	if (flags >= 0) {
		LOGD("fcntl nonblocking");
		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
			LOGE("fcntl(%d, F_SETFL)", fd);
			return -1;
		} else {
			LOGD("fcntl(%d, F_SETFL)");
		}
	}

	return 0;
}

static int _mmsvc_core_check_server_is_running(void)
{
	int fd, already_running;
	int ret = -1;

	LOGD("Enter");

	/* First, check whether the existing file is locked. */
	fd = open(LOCKFILE, O_RDONLY);
	if (fd == -1 && errno != ENOENT) {
		/* Cannot open file, but it's not because the file doesn't exist. */
		char msg[1024];
		snprintf(msg, sizeof(msg), "datserver: Cannot open lock file %s", LOCKFILE);
		LOGE("open failed: %s ", msg);
		return ret;
	} else if (fd != -1) {
		already_running = flock(fd, LOCK_EX | LOCK_NB) == -1;
		close(fd);
		if (already_running) {
			LOGE("File already locked. There's already a server running");
			return 0;
		}
	}

	/* Lock file does not exist, or is not locked. Create a new lockfile and lock it. */
	fd = open(LOCKFILE, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (fd == -1) {
		LOGE("dataserver: Cannot create lock file");
		return ret;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
		LOGE("Can't lock the lock file \"%s\". " "Is another instance running?", LOCKFILE);
		return ret;
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);

	LOGD("Leave");
	return 1;
}

static bool _mmsvc_core_attach_server(int fd, MMSVC_CORE_ClientCallback callback, gpointer param)
{
	GIOChannel *channel;
	GSource *src = NULL;

	LOGD("Enter");

	channel = g_io_channel_unix_new(fd);
	if (!channel) {
		return false;
	}

	src = g_io_create_watch(channel, G_IO_IN);
	if (!src) {
		return false;
	}

	g_source_set_callback(src, (GSourceFunc) callback, param, NULL);

	g_source_attach(src, g_main_loop_get_context(g_loop));
	g_source_unref(src);

	return true;
}

static MMServer *_mmsvc_core_create_new_server_from_fd(int fd[], int type)
{
	MMServer *server;
	int i;

	LOGD("Enter");
	server = malloc(sizeof(MMServer));
	g_return_val_if_fail(server != NULL, NULL);

	server->fd = fd[MUSED_CHANNEL_MSG];
	server->data_fd = fd[MUSED_CHANNEL_DATA];
	server->type = type;
	server->stop = 0;
	server->retval = 0;

	/*initiate server */
	g_atomic_int_set(&server->running, 1);

	for (i = 0; i < MUSED_CHANNEL_MAX; i++) {
		if (!_mmsvc_core_attach_server(fd[i],
					_mmsvc_core_connection_handler, (gpointer) i)) {
			LOGD("Fail to attach server fd %d", fd[i]);
			MMSVC_FREE(server);
			return NULL;
		}
	}

	LOGD("Leave");
	return server;
}

static int _mmsvc_core_free(MMServer *server)
{
	int retval = -1;
	int i;
	LOGD("Enter");

	g_return_val_if_fail(server != NULL, retval);

	retval = server->retval;
	close(server->fd);
	for (i = 0; i < MUSED_CHANNEL_MAX; i++)
		remove(UDS_files[i]);
	remove(LOCKFILE);
	MMSVC_FREE(server);
	mmsvc_core_workqueue_get_instance()->shutdown();
	LOGD("Leave");
	return retval;
}

gpointer mmsvc_core_main_loop(gpointer data)
{
	while (1) {
		sleep(LOG_SLEEP_TIMER);
		LOGD("polling %d\n", g_main_loop_is_running(g_loop));
	}

	return NULL;
}

int _mmsvc_core_server_new(mused_channel_e channel)
{
	int fd;
	struct sockaddr *address;
	struct sockaddr_un addr_un;
	socklen_t address_len;

	if (channel >= MUSED_CHANNEL_MAX)
		return -1;

	unlink(UDS_files[channel]);
	LOGD("Enter");

	/* Create Socket */
	fd = socket(AF_UNIX, SOCK_STREAM, 0); /* Unix Domain Socket */
	if (fd < 0) {
		LOGE("socket failed sock: %s", strerror(errno));
		return -1;
	} else {
		LOGD("fd: %d", fd);
	}

	memset(&addr_un, 0, sizeof(addr_un));
	addr_un.sun_family = AF_UNIX;
	strncpy(addr_un.sun_path, UDS_files[channel], sizeof(addr_un.sun_path));
	address_len = sizeof(addr_un);
	address = (struct sockaddr *)(&addr_un);

	/* Bind to filename */
	if (bind(fd, address, address_len) < 0) {
		if (errno == EADDRINUSE) {
			LOGE("%d is address in using so remove the file of %s", fd, addr_un.sun_path);
			unlink(addr_un.sun_path);
		}

		if (bind(fd, (struct sockaddr *)&addr_un, sizeof(addr_un)) != 0)
			LOGE("bind failed sock: %s", strerror(errno));
		else
			LOGE("bind failed sock: %s", strerror(errno));
		close(fd);
		return -1;
	}

	/* Setup listen queue */
	if (listen(fd, 5) == -1) {
		LOGE("listen failed");
		close(fd);
		return -1;
	}

	if (_mmsvc_core_set_nonblocking(fd) < 0)
		LOGE("failed to set server socket to non-blocking");

	LOGD("Leave");

	return fd;
}


MMServer *mmsvc_core_new()
{
	int fd[MUSED_CHANNEL_MAX];
	int i;
	LOGD("Enter");

	for (i = 0; i < MUSED_CHANNEL_MAX; i++) {
		fd[i] = _mmsvc_core_server_new(i);
		if (fd[i] < 0) {
			LOGE("Failed to create socket server %d", i);
			return NULL;
		}
	}

	/* Initialize work queue */
	if (mmsvc_core_workqueue_init(WORK_THREAD_NUM)) {
		LOGE("mmsvc_core_new : Failed to initialize the workqueue");
		for (i = 0; i < MUSED_CHANNEL_MAX; i++)
			close(fd[i]);
		mmsvc_core_workqueue_get_instance()->shutdown();
		return NULL;
	}

	LOGD("Leave");

	return _mmsvc_core_create_new_server_from_fd(fd, READ|PERSIST);
}

static gboolean _mmsvc_core_connection_handler(GIOChannel *source,
		GIOCondition condition, gpointer data)
{
	int client_sockfd, server_sockfd;
	socklen_t client_len;
	struct sockaddr_un client_address;
	mused_channel_e channel = (mused_channel_e)data;

	LOGD("Enter");

	Client client = NULL;
	mmsvc_core_workqueue_job_t *job = NULL;

	server_sockfd = g_io_channel_unix_get_fd(source);

	client_len = sizeof(client_address);
	client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_address, &client_len);
	LOGD("server: %d client: %d", server_sockfd, client_sockfd);

	if (client_sockfd < 0) {
		LOGE("failed to accept");
		goto out;
	}

	if (channel == MUSED_CHANNEL_MSG) {
		if ((client = malloc(sizeof(_Client))) == NULL) {
			LOGE("failed to allocated memory for client stat");
			goto out;
		}

		memset(client, 0, sizeof(_Client));
		client->ch[channel].fd = client_sockfd;
	}

	if ((job = malloc(sizeof(mmsvc_core_workqueue_job_t))) == NULL) {
		LOGE("failed to allocate memory for job state");
		goto out;
	}

	job->job_function = job_functions[channel];
	if (channel == MUSED_CHANNEL_MSG)
		job->user_data = client;
	else
		job->user_data = (void *)client_sockfd;

	mmsvc_core_workqueue_get_instance()->add_job(job);

	LOGD("Leave");
	return TRUE;
out:
	if (client_sockfd)
		close(client_sockfd);

	MMSVC_FREE(client);
	MMSVC_FREE(job);

	LOGE("FALSE");
	return FALSE;
}

int mmsvc_core_run()
{
	int ret = -1;

	LOGD("Enter");

	ret = _mmsvc_core_check_server_is_running();
	if (ret == -1) {
		return -1;
	} else if (ret == 0) {
		LOGE("Server is already running");
		return 2;
	}

	/* Sigaction */
	g_loop = g_main_loop_new(NULL, FALSE);

	g_thread = g_thread_new("mmsvc_thread", mmsvc_core_main_loop, g_loop);

	server = mmsvc_core_new();
	if (!server) {
		g_main_loop_unref(g_loop);
		return 1;
	}

	LOGD("g_main_loop_run");
	g_main_loop_run(g_loop);

	LOGD("Leave");
	return _mmsvc_core_free(server);
}

static int _mmsvc_core_client_new(mused_channel_e channel)
{
	struct sockaddr_un address;
	int len, ret = -1;
	int sockfd;

	if (channel >= MUSED_CHANNEL_MAX)
		return -1;

	LOGD("Enter");

	/*Create socket*/
	if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
		LOGE("[socket failure] sock: %s", strerror(errno));
		return ret;
	} else {
		LOGD("sockfd: %d", sockfd);
		if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) < 0) {
			LOGE("unable to set on ctrls socket fd %d: %s", sockfd, strerror(errno));
			(void) close(sockfd);
			return -1;
		}
		LOGD("fcntl");
	}

	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, UDS_files[channel], sizeof(address.sun_path));
	len = sizeof(address);

	if ((ret = connect(sockfd, (struct sockaddr *)&address, len)) < 0) {
		LOGE("connect failure");
		if (sockfd)
			(void) close(sockfd);
		return ret;
	}

	LOGD("Leave");
	return sockfd;
}

int mmsvc_core_client_new(void)
{
	return _mmsvc_core_client_new(MUSED_CHANNEL_MSG);
}

int mmsvc_core_client_new_data_ch(void)
{
	return _mmsvc_core_client_new(MUSED_CHANNEL_DATA);
}

int mmsvc_core_client_get_msg_fd(Client client)
{
	g_return_val_if_fail(client, -1);

	return client->ch[MUSED_CHANNEL_MSG].fd;
}

int mmsvc_core_client_get_data_fd(Client client)
{
	g_return_val_if_fail(client, -1);

	return client->ch[MUSED_CHANNEL_DATA].fd;
}
void mmsvc_core_client_set_cust_data(Client client, void *data)
{
	g_return_if_fail(client);
	client->cust_data = data;
}

void *mmsvc_core_client_get_cust_data(Client client)
{
	g_return_val_if_fail(client, NULL);
	return client->cust_data;
}

char *mmsvc_core_client_get_msg(Client client)
{
	g_return_val_if_fail(client, NULL);
	return (client->recvMsg + client->msg_offset);
}

int mmsvc_core_client_get_capi(Client client)
{
	g_return_val_if_fail(client, -1);
	return client->api_client;
}

void mmsvc_core_connection_close(int sock_fd)
{
	LOGD("Enter");
	if (sock_fd > 0) {
		shutdown(sock_fd, SHUT_RDWR);
		close(sock_fd);
	}

	LOGD("Leave");
}

void mmsvc_core_worker_exit(Client client)
{
	LOGD("Enter");
	if (!client) {
		LOGE("Error - null client");
		return;
	}

	mmsvc_core_connection_close(client->ch[MUSED_CHANNEL_MSG].fd);
	mmsvc_core_connection_close(client->ch[MUSED_CHANNEL_DATA].fd);
	if (!client->ch[MUSED_CHANNEL_MSG].p_gthread) {
		LOGE("Error - null p_gthread");
		return;
	}
	LOGD("%p thread exit\n", client->ch[MUSED_CHANNEL_MSG].p_gthread);
	g_thread_unref(client->ch[MUSED_CHANNEL_MSG].p_gthread);

	if (client->ch[MUSED_CHANNEL_DATA].p_gthread)
		g_thread_unref(client->ch[MUSED_CHANNEL_DATA].p_gthread);
	MMSVC_FREE(client);

	mmsvc_core_config_get_instance()->free();

	LOGD("Leave");
	g_thread_exit(NULL);
}
