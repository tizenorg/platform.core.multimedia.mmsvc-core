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

#include "muse_core.h"
#include "muse_core_private.h"
#include "muse_core_config.h"
#include "muse_core_internal.h"
#include "muse_core_log.h"
#include "muse_core_ipc.h"
#include "muse_core_msg_json.h"
#include "muse_core_module.h"

#define END_DELIM '}'
#define RECV_ERR -1

typedef struct muse_recv_data_head {
	unsigned int marker;
	uint64_t id;
	int size;
} muse_recv_data_head_t;

typedef struct muse_recv_data {
	muse_recv_data_head_t header;
	/* Dynamic allocated data area */
} muse_recv_data_t;

static muse_core_ipc_t *g_muse_core_ipc = NULL;

static void _muse_core_ipc_client_cleanup(muse_module_h module);
static gpointer _muse_core_ipc_dispatch_worker(gpointer data);
static gpointer _muse_core_ipc_data_worker(gpointer data);
static muse_recv_data_t *_muse_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize);
static bool _muse_core_ipc_msg_complete_confirm(muse_client_h client, char *msg, int msg_len);
static bool _muse_core_ipc_init_bufmgr(void);
static void _muse_core_ipc_deinit_bufmgr(void);
static void _muse_core_ipc_client_free(gpointer key, gpointer value, gpointer user_data);
static void _muse_core_ipc_free(void);
static void _muse_core_ipc_init_instance(void (*free)(void));

static void _muse_core_ipc_client_cleanup(muse_module_h module)
{
	g_return_if_fail(module != NULL);

	muse_core_log_get_instance()->flush_msg();
	g_hash_table_foreach(g_muse_core_ipc->client_table, (GHFunc)_muse_core_ipc_client_free, NULL);

	g_queue_free(module->ch[MUSE_CHANNEL_DATA].queue);
	module->ch[MUSE_CHANNEL_DATA].queue = NULL;
	g_cond_broadcast(&module->ch[MUSE_CHANNEL_DATA].cond);

	if (module->ch[MUSE_CHANNEL_DATA].p_gthread) {
		g_thread_join(module->ch[MUSE_CHANNEL_DATA].p_gthread);
		module->ch[MUSE_CHANNEL_DATA].p_gthread = NULL;
	}
	g_mutex_clear(&module->ch[MUSE_CHANNEL_DATA].mutex);
	g_cond_clear(&module->ch[MUSE_CHANNEL_DATA].cond);
	LOGD("worker exit");
	muse_core_worker_exit(module);
}

static gpointer _muse_core_ipc_dispatch_worker(gpointer data)
{
	int len, parse_len, cmd, api_module;
	muse_module_h module = NULL;
	muse_core_msg_parse_err_e err = MUSE_MSG_PARSE_ERROR_NONE;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};
	g_return_val_if_fail(data != NULL, NULL);

	module = (muse_module_h)data;
	g_return_val_if_fail(module != NULL, NULL);

	while (1) {
		memset(module->recvMsg, 0x00, sizeof(module->recvMsg));
		len = muse_core_ipc_recv_msg(module->ch[MUSE_CHANNEL_MSG].fd, module->recvMsg);
		if (len <= 0) {
			strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
			LOGE("recv : %s (%d)", err_msg, errno);
			muse_core_cmd_dispatch(module, MUSE_MODULE_COMMAND_SHUTDOWN);
			_muse_core_ipc_client_cleanup(module);
		} else {
			parse_len = len;
			cmd = 0;
			api_module = 0;
			module->msg_offset = 0;

			muse_core_log_get_instance()->log(module->recvMsg);

			while (module->msg_offset < len) {
				if (muse_core_msg_json_deserialize(MUSE_API, module->recvMsg + module->msg_offset, &parse_len, &cmd, &err, MUSE_TYPE_INT)) {
					switch (cmd) {
					module->disp_api = cmd;
					case API_CREATE:
						LOGD("CREATE");
						if (muse_core_msg_json_deserialize(MUSE_MODULE, module->recvMsg + module->msg_offset, &parse_len, &api_module, &err, MUSE_TYPE_INT)) {
							module->api_module = api_module;
							module->is_create_api_called = true;
							module->ch[MUSE_CHANNEL_MSG].dll_handle = muse_core_module_get_instance()->load(api_module);
							muse_core_cmd_dispatch(module, MUSE_MODULE_COMMAND_CREATE_SERVER_ACK);
							module->ch[MUSE_CHANNEL_DATA].queue = g_queue_new();
							g_mutex_init(&module->ch[MUSE_CHANNEL_DATA].mutex);
							LOGD("module fd: %d dll_handle: %p", module->ch[MUSE_CHANNEL_MSG].fd, module->ch[MUSE_CHANNEL_MSG].dll_handle);
							muse_core_module_get_instance()->dispatch(cmd, module);
						}
						break;
					case API_DESTROY:
						LOGD("DESTROY");
						muse_core_module_get_instance()->dispatch(cmd, module);
						_muse_core_ipc_client_cleanup(module);
						break;
					default:
						if (muse_core_module_get_instance()->get_dllsymbol_loaded_value(module->api_module) == false) {
							LOGE("Please check whether it has really intended to not call the create api");
							module->is_create_api_called = false;
							if (muse_core_msg_json_deserialize(MUSE_MODULE, module->recvMsg + module->msg_offset, &parse_len, &api_module, &err, MUSE_TYPE_INT)) {
								module->api_module = api_module;
								module->ch[MUSE_CHANNEL_MSG].dll_handle = muse_core_module_get_instance()->load(api_module);
								module->ch[MUSE_CHANNEL_DATA].queue = g_queue_new();
								g_mutex_init(&module->ch[MUSE_CHANNEL_DATA].mutex);
							}
						}
						muse_core_module_get_instance()->dispatch(cmd, module);
						if (module->is_create_api_called == false)
							_muse_core_ipc_client_cleanup(module);
						break;
					}
				} else {
					LOGE("Parsing status : %d", err);
					break;
				}

				if (parse_len == 0)
					break;

				module->msg_offset += parse_len;
				parse_len = len - parse_len;
			}
		}
	}

	LOGD("Leave");
	return NULL;
}

static gpointer _muse_core_ipc_data_worker(gpointer data)
{
	int recvLen = 0;
	int currLen = 0;
	intptr_t fd = (intptr_t) data;
	muse_module_h module = NULL;
	char *recvBuff = NULL;
	int allocSize = 0;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};
	g_return_val_if_fail(fd > 0, NULL);

	while (1) {
		if (!recvBuff) {
			allocSize = MUSE_MSG_MAX_LENGTH;
			recvBuff = g_new(char, allocSize);
		}
		if (!recvBuff) {
			LOGE("Out of memory");
			break;
		}
		recvLen = muse_core_ipc_recv_msg(fd, recvBuff + currLen);
		currLen += recvLen;
		LOGD("buff %p, recvLen %d, currLen %d, allocSize %d", recvBuff, recvLen, currLen, allocSize);
		if (recvLen <= 0) {
			strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
			LOGE("[%d] recv : %s (%d)", fd, err_msg, errno);
			break;
		} else {
			if (module) {
				muse_recv_data_t *qData;
				while ((qData = _muse_core_ipc_new_qdata(&recvBuff, currLen, &allocSize)) != NULL) {
					int qDataSize = qData->header.size + sizeof(muse_recv_data_head_t);
					if (currLen > qDataSize) {
						allocSize = allocSize - qDataSize;
						char *newBuff = g_new(char, allocSize);
						memcpy(newBuff, recvBuff + qDataSize, currLen - qDataSize);
						recvBuff = newBuff;
					}
					g_queue_push_tail(module->ch[MUSE_CHANNEL_DATA].queue, qData);
					g_cond_signal(&module->ch[MUSE_CHANNEL_DATA].cond);

					currLen = currLen - qDataSize;
					if (!currLen)
						break;
				}
				if (!currLen) {
					recvBuff = NULL;
				} else if (allocSize < MUSE_MSG_MAX_LENGTH + currLen) {
					allocSize = MUSE_MSG_MAX_LENGTH + currLen;
					recvBuff = g_renew(char, recvBuff, allocSize);
				}
			} else {
				intptr_t module_addr = 0;
				if (muse_core_msg_json_deserialize(MUSE_MODULE_ADDR, recvBuff, NULL, &module_addr, NULL, MUSE_TYPE_POINTER)) {
					module = (muse_module_h) module_addr;
					if (module) {
						module->ch[MUSE_CHANNEL_DATA].p_gthread = g_thread_self();
						g_return_val_if_fail(module->ch[MUSE_CHANNEL_DATA].p_gthread != NULL, NULL);
					}
				}
				MUSE_FREE(recvBuff);
				recvBuff = NULL;
				currLen = 0;
			}
		}
	}

	MUSE_FREE(recvBuff);

	LOGD("Leave");
	return NULL;
}

static muse_recv_data_t *_muse_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize)
{
	int qDataSize;
	muse_recv_data_t *qData = (muse_recv_data_t *)*recvBuff;
	g_return_val_if_fail(recvBuff, NULL);

	if (qData->header.marker != MUSE_DATA_HEAD) {
		LOGE("Invalid data header");
		return NULL;
	}
	qDataSize = qData->header.size + sizeof(muse_recv_data_head_t);
	if (qDataSize > recvSize) {
		LOGD("recv is not completed");
		if (qDataSize > *allocSize) {
			LOGD("Realloc %d -> %d", *allocSize, qDataSize);
			*allocSize = qDataSize;
			*recvBuff = g_renew(char, *recvBuff, *allocSize);
		}
		return NULL;
	}

	return qData;
}

static bool _muse_core_ipc_msg_complete_confirm(muse_client_h client, char *msg, int msg_len)
{
	char *ptr = NULL;
	size_t ptr_len = 0;

	g_return_val_if_fail(client != NULL, TRUE);
	g_return_val_if_fail(msg != NULL, TRUE);

	if (msg_len == MUSE_MSG_MAX_LENGTH || client->is_ever_broken == TRUE) {
		ptr = strrchr(msg, END_DELIM);
		g_return_val_if_fail(ptr != NULL, TRUE);
		ptr_len = strlen(ptr) - 1;

		if (ptr_len > 0) {
			client->is_ever_broken = TRUE;
			int idx = ptr - msg;
			memcpy(client->cache, ptr + 1, ptr_len);
			client->cache_len = ptr_len;
			msg[idx + 1] = '\0';
			return FALSE;
		}
	}

	return TRUE;
}

static bool _muse_core_ipc_init_bufmgr(void)
{
	LOGD("Enter");
	g_return_val_if_fail(g_muse_core_ipc != NULL, FALSE);

	g_muse_core_ipc->bufmgr = tbm_bufmgr_init(-1);
	if (g_muse_core_ipc->bufmgr == NULL) {
		LOGE("Error - tbm_bufmgr_init");
		return FALSE;
	}
	LOGD("bufmgr: 0x%x", g_muse_core_ipc->bufmgr);

	LOGD("Leave");
	return TRUE;
}

static void _muse_core_ipc_deinit_bufmgr(void)
{
	LOGD("Enter");

	g_return_if_fail(g_muse_core_ipc->bufmgr);

	tbm_bufmgr_deinit(g_muse_core_ipc->bufmgr);

	LOGD("Leave");
}

static void _muse_core_ipc_client_new(int sock_fd, muse_client_h client)
{
	g_return_if_fail(g_muse_core_ipc != NULL);
	g_return_if_fail(g_muse_core_ipc->client_table != NULL);
	g_return_if_fail(g_muse_core_ipc->key != NULL);

	*(g_muse_core_ipc->key) = sock_fd;

	g_hash_table_insert(g_muse_core_ipc->client_table, g_muse_core_ipc->key, (gpointer)client);
}

static void _muse_core_ipc_client_free(gpointer key, gpointer value, gpointer user_data)
{
	g_hash_table_remove(g_muse_core_ipc->client_table, key);
}

static void _muse_core_ipc_free(void)
{
	LOGD("Enter");

	_muse_core_ipc_deinit_bufmgr();

	g_return_if_fail(g_muse_core_ipc != NULL);

	g_hash_table_destroy(g_muse_core_ipc->client_table);
	MUSE_FREE(g_muse_core_ipc->key);
	MUSE_FREE(g_muse_core_ipc);

	LOGD("Leave");
}

static void _muse_core_ipc_init_instance(void (*free)(void))
{
	g_return_if_fail(free != NULL);
	g_return_if_fail(g_muse_core_ipc == NULL);

	g_muse_core_ipc = calloc(1, sizeof(*g_muse_core_ipc));
	g_return_if_fail(g_muse_core_ipc != NULL);
	g_muse_core_ipc->client_table = g_hash_table_new(g_int_hash, g_int_equal);
	g_return_if_fail(g_muse_core_ipc->client_table != NULL);

	g_return_if_fail(_muse_core_ipc_init_bufmgr() == TRUE);
	g_muse_core_ipc->key = g_new(gint, 1);
	g_return_if_fail(g_muse_core_ipc->key != NULL);

	g_muse_core_ipc->free = free;
}

int muse_core_ipc_get_client_from_job(muse_core_workqueue_job_t *job)
{
	LOGD("Enter");
	muse_module_h module = NULL;

	g_return_val_if_fail(job != NULL, MM_ERROR_INVALID_ARGUMENT);

	module = (muse_module_h) job->user_data;
	g_return_val_if_fail(module != NULL, MM_ERROR_INVALID_ARGUMENT);

	LOGD("Leave");
	return module->api_module;
}

gboolean muse_core_ipc_job_function(muse_core_workqueue_job_t *job)
{
	LOGD("Enter");
	muse_module_h module = NULL;
	muse_client_h client = NULL;
	GError *error = NULL;
	char fd_name[MAX_ERROR_MSG_LEN];

	g_return_val_if_fail(job != NULL, FALSE);

	module = (muse_module_h) job->user_data;
	g_return_val_if_fail(module != NULL, FALSE);

	LOGD("[%p] client's fd : %d", module, module->ch[MUSE_CHANNEL_MSG].fd);

	client = calloc(1, sizeof(muse_client_t));
	g_return_val_if_fail(client != NULL, FALSE);

	_muse_core_ipc_client_new(module->ch[MUSE_CHANNEL_MSG].fd, client);

	snprintf(fd_name, sizeof(fd_name), "fd_%d", module->ch[MUSE_CHANNEL_MSG].fd);
	module->ch[MUSE_CHANNEL_MSG].p_gthread = g_thread_try_new(fd_name, _muse_core_ipc_dispatch_worker, (gpointer)module, &error);
	if (module->ch[MUSE_CHANNEL_MSG].p_gthread == NULL && error) {
		LOGE("%s %s", fd_name, error->message);
		module->ch[MUSE_CHANNEL_MSG].dll_handle = muse_core_module_get_instance()->load(API_CREATE);
		muse_core_cmd_dispatch(module, MUSE_MODULE_COMMAND_RESOURCE_NOT_AVAILABLE);
	}

	MUSE_FREE(job);
	g_return_val_if_fail(module->ch[MUSE_CHANNEL_MSG].p_gthread != NULL, FALSE);

	LOGD("Leave");
	return TRUE;
}

gboolean muse_core_ipc_data_job_function(muse_core_workqueue_job_t *job)
{
	LOGD("Enter");
	intptr_t fd;
	GError *error = NULL;
	GThread *p_gthread = NULL;
	char fd_name[MAX_ERROR_MSG_LEN];

	g_return_val_if_fail(job != NULL, FALSE);

	fd = (intptr_t) job->user_data;
	g_return_val_if_fail(fd > 0, FALSE);

	LOGD("data channel fd : %d", fd);

	snprintf(fd_name, sizeof(fd_name), "fd_%d", (int)fd);
	p_gthread = g_thread_try_new(fd_name, _muse_core_ipc_data_worker, GINT_TO_POINTER(fd), &error);

	MUSE_FREE(job);
	g_return_val_if_fail(p_gthread != NULL, FALSE);

	LOGD("Leave");
	return TRUE;
}

int muse_core_ipc_send_msg(int sock_fd, const char *msg)
{
	int ret = MM_ERROR_NONE;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	g_return_val_if_fail(msg != NULL, MM_ERROR_INVALID_ARGUMENT);

	if ((ret = send(sock_fd, msg, strlen(msg), 0)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("fail to send msg (%s)", err_msg);
	}

	return ret;
}

int muse_core_ipc_recv_msg(int sock_fd, char *msg)
{
	int ret = MM_ERROR_NONE;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	g_return_val_if_fail(msg != NULL, RECV_ERR);

	if ((ret = recv(sock_fd, msg, MUSE_MSG_MAX_LENGTH, 0)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("fail to receive msg (%s)", err_msg);
	} else if (ret > 0) {
		msg[ret] = '\0';
	}

	return ret;
}

int muse_core_ipc_recv_msg_server(int sock_fd, char *msg)
{
	int ret = MM_ERROR_NONE;
	int recv_len = 0;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	g_return_val_if_fail(msg != NULL, RECV_ERR);

	*(g_muse_core_ipc->key) = sock_fd;
	muse_client_h client = g_hash_table_lookup(g_muse_core_ipc->client_table, g_muse_core_ipc->key);

	g_return_val_if_fail(client != NULL, RECV_ERR);

	if (client->cache_len > 0)
		memcpy(msg, client->cache, client->cache_len);

	recv_len = MUSE_MSG_MAX_LENGTH - client->cache_len;

	if ((ret = recv(sock_fd, msg + client->cache_len, recv_len, 0)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("fail to receive msg (%s)", err_msg);
	} else if (ret > 0) {
		if (client->cache_len > 0) {
			ret += client->cache_len;
			client->cache_len = 0;
		}
		msg[ret] = '\0';
		if (_muse_core_ipc_msg_complete_confirm(client, msg, ret) == FALSE)
			LOGW("%s", client->cache);
	}

	return ret;
}

int muse_core_ipc_recv_msg_client(muse_client_h client, char *msg)
{
	int ret = MM_ERROR_NONE;
	int recv_len = 0;
	char err_msg[MAX_ERROR_MSG_LEN] = {'\0',};

	g_return_val_if_fail(client != NULL, RECV_ERR);
	g_return_val_if_fail(msg != NULL, RECV_ERR);

	if (client->cache_len > 0)
		memcpy(msg, client->cache, client->cache_len);

	recv_len = MUSE_MSG_MAX_LENGTH - client->cache_len;

	if ((ret = recv(client->fd, msg + client->cache_len, recv_len, 0)) < 0) {
		strerror_r(errno, err_msg, MAX_ERROR_MSG_LEN);
		LOGE("fail to receive msg (%s)", err_msg);
	} else if (ret > 0) {
		if (client->cache_len > 0) {
			ret += client->cache_len;
			client->cache_len = 0;
		}
		msg[ret] = '\0';
		if (_muse_core_ipc_msg_complete_confirm(client, msg, ret) == FALSE)
			LOGW("%s", client->cache);
	}

	return ret;
}

void muse_core_ipc_set_timeout(int sock_fd, unsigned long timeout_sec)
{
	LOGD("Enter");
	struct timeval tv;
	tv.tv_sec  = timeout_sec;
	tv.tv_usec = 0L;

	setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv));
	LOGD("Leave");
}

int muse_core_ipc_push_data(int sock_fd, const char *data, int size, uint64_t data_id)
{
	int ret = MM_ERROR_NONE;

	muse_recv_data_head_t header;
	g_return_val_if_fail(data != NULL, MM_ERROR_INVALID_ARGUMENT);

	header.marker = MUSE_DATA_HEAD;
	header.size = size;
	header.id = data_id;

	if ((ret = send(sock_fd, &header, sizeof(muse_recv_data_head_t), 0)) < 0)
		LOGE("fail to send msg");
	if ((ret += send(sock_fd, data, size, 0)) < 0)
		LOGE("fail to send msg");

	return ret;
}

void muse_core_ipc_delete_data(char *data)
{
	muse_recv_data_t *qData;
	g_return_if_fail(data);

	qData = (muse_recv_data_t *)(data - sizeof(muse_recv_data_head_t));
	if (qData && qData->header.marker == MUSE_DATA_HEAD)
		MUSE_FREE(qData);
}

char *muse_core_ipc_get_data(muse_module_h module)
{
	muse_recv_data_t *qData;
	char *rawData;
	muse_core_channel_info_t *ch;
	gint64 end_time = g_get_monotonic_time() + 100 * G_TIME_SPAN_MILLISECOND;
	g_return_val_if_fail(module, NULL);
	ch = &module->ch[MUSE_CHANNEL_DATA];
	g_return_val_if_fail(ch->queue, NULL);

	g_mutex_lock(&ch->mutex);
	if (g_queue_is_empty(ch->queue))
		g_cond_wait_until(&ch->cond, &ch->mutex, end_time);
	g_mutex_unlock(&ch->mutex);

	qData = g_queue_pop_head(ch->queue);
	if (qData) {
		rawData = (char *)qData + sizeof(muse_recv_data_head_t);
		return rawData;
	}

	return NULL;
}

intptr_t muse_core_ipc_get_handle(muse_module_h module)
{
	g_return_val_if_fail(module, NULL);
	g_return_val_if_fail(module->handle, NULL);
	return module->handle;
}

int muse_core_ipc_set_handle(muse_module_h module, intptr_t handle)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(handle, MM_ERROR_INVALID_HANDLE);

	module->handle = handle;
	return MM_ERROR_NONE;
}

int muse_core_ipc_get_bufmgr(tbm_bufmgr *bufmgr)
{
	LOGD("Enter");
	g_return_val_if_fail(bufmgr, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(g_muse_core_ipc->bufmgr, MM_ERROR_INVALID_ARGUMENT);

	LOGD("bufmgr: 0x%x", g_muse_core_ipc->bufmgr);
	*bufmgr = g_muse_core_ipc->bufmgr;
	LOGD("Leave");
	return MM_ERROR_NONE;
}

muse_core_ipc_t *muse_core_ipc_get_instance(void)
{
	if (g_muse_core_ipc == NULL)
		_muse_core_ipc_init_instance(_muse_core_ipc_free);

	return g_muse_core_ipc;
}

void muse_core_ipc_init(void)
{
	LOGD("Enter");

	if (g_muse_core_ipc == NULL)
		_muse_core_ipc_init_instance(_muse_core_ipc_free);

	LOGD("Leave");
}
