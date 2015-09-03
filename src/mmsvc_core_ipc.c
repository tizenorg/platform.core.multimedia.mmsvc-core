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
#include "mmsvc_core_log.h"
#include "mmsvc_core_ipc.h"
#include "mmsvc_core_msg_json.h"
#include "mmsvc_core_module.h"

typedef struct {
	int marker;
	int id;
	int size;
} RecvDataHead_t;

typedef struct {
	RecvDataHead_t header;
	/* Dynamic allocated data area */
} RecvData_t;

static void _mmsvc_core_ipc_client_cleanup(Client client);
static gpointer _mmsvc_core_ipc_dispatch_worker(gpointer data);
static gpointer _mmsvc_core_ipc_data_worker(gpointer data);
static RecvData_t *_mmsvc_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize);

static void _mmsvc_core_ipc_client_cleanup(Client client)
{
	g_return_if_fail(client != NULL);

	g_queue_free(client->ch[MUSED_CHANNEL_DATA].queue);
	client->ch[MUSED_CHANNEL_DATA].queue = NULL;
	g_cond_broadcast(&client->ch[MUSED_CHANNEL_DATA].cond);
	g_thread_join(client->ch[MUSED_CHANNEL_DATA].p_gthread);
	g_mutex_clear(&client->ch[MUSED_CHANNEL_DATA].mutex);
	g_cond_clear(&client->ch[MUSED_CHANNEL_DATA].cond);
	LOGD("worker exit");
	mmsvc_core_worker_exit(client);
}

static gpointer _mmsvc_core_ipc_dispatch_worker(gpointer data)
{
	int len, parse_len, cmd, api_client;
	Client client = NULL;
	intptr_t handle = 0;
	mused_msg_parse_err_e err = MUSED_MSG_PARSE_ERROR_NONE;
	g_return_val_if_fail(data != NULL, NULL);

	client = (Client)data;
	g_return_val_if_fail(client != NULL, NULL);

	while (1) {
		memset(client->recvMsg, 0x00, sizeof(client->recvMsg));
		len = mmsvc_core_ipc_recv_msg(client->ch[MUSED_CHANNEL_MSG].fd, client->recvMsg);
		if (len <= 0) {
			LOGE("recv : %s (%d)", strerror(errno), errno);
			mmsvc_core_cmd_dispatch(client, MUSED_DOMAIN_EVENT_SHUTDOWN);
			mmsvc_core_cmd_dispatch(client, MUSED_DOMAIN_EVENT_DUMP);
			_mmsvc_core_ipc_client_cleanup(client);
		} else {
			parse_len = len;
			LOGD("Message In");
			cmd = 0;
			api_client = 0;
			client->msg_offset = 0;

			mmsvc_core_log_get_instance()->log(client->recvMsg);

			while (client->msg_offset < len) {
				if (mmsvc_core_msg_json_deserialize_len("api", client->recvMsg + client->msg_offset, &parse_len, &cmd, &err, MUSED_TYPE_INT)) {
					if (mmsvc_core_msg_json_deserialize_len("handle", client->recvMsg + client->msg_offset, &parse_len, &handle, &err, MUSED_TYPE_POINTER))
						client->handle = handle;
					switch (cmd) {
					case API_CREATE:
						if (mmsvc_core_msg_json_deserialize_len("client", client->recvMsg + client->msg_offset, &parse_len, &api_client, &err, MUSED_TYPE_INT)) {
							client->api_client = api_client;
							client->ch[MUSED_CHANNEL_MSG].module = mmsvc_core_module_load(api_client);
							client->ch[MUSED_CHANNEL_DATA].queue = g_queue_new();
							g_mutex_init(&client->ch[MUSED_CHANNEL_DATA].mutex);
							g_cond_init(&client->ch[MUSED_CHANNEL_DATA].cond);
							LOGD("client fd: %d module: %p",
									client->ch[MUSED_CHANNEL_MSG].fd,
									client->ch[MUSED_CHANNEL_MSG].module);
							mmsvc_core_module_dll_symbol_dispatch(cmd, client);
							break;
						}
					case API_DESTROY:
						LOGD("DESTROY");
						mmsvc_core_module_dll_symbol_dispatch(cmd, client);
						_mmsvc_core_ipc_client_cleanup(client);
						break;
					default:
						LOGD("[default] client->module: %p", client->ch[MUSED_CHANNEL_MSG].module);
						mmsvc_core_module_dll_symbol_dispatch(cmd, client);
						break;
					}
				} else {
					LOGE("Parsing status : %d", err);
					break;
				}

				if (parse_len == 0)
					break;

				client->msg_offset += parse_len;
				parse_len = len - parse_len;
			}
		}
	}

	LOGD("Leave");
	return NULL;
}

static gpointer _mmsvc_core_ipc_data_worker(gpointer data)
{
	int recvLen = 0;
	int currLen = 0;
	intptr_t fd = (intptr_t) data;
	Client client = NULL;
	char *recvBuff = NULL;
	int allocSize = 0;

	g_return_val_if_fail(fd > 0, NULL);

	while(1) {
		if (!recvBuff) {
			allocSize = MM_MSG_MAX_LENGTH;
			recvBuff = g_new(char, allocSize);
		}
		if (!recvBuff) {
			LOGE("Out of memory");
			break;
		}
		recvLen = mmsvc_core_ipc_recv_msg(fd, recvBuff + currLen);
		currLen += recvLen;
		LOGD("buff %p, recvLen %d, currLen %d, allocSize %d",
				recvBuff, recvLen, currLen, allocSize);
		if (recvLen <= 0) {
			LOGE("recv : %s (%d)", strerror(errno), errno);
			break;
		} else {
			if (client) {
				RecvData_t *qData;
				while ((qData = _mmsvc_core_ipc_new_qdata(&recvBuff, currLen, &allocSize))
						!= NULL) {
					int qDataSize = qData->header.size + sizeof(RecvDataHead_t);
					if (currLen > qDataSize) {
						allocSize = allocSize - qDataSize;
						char *newBuff = g_new(char, allocSize);
						memcpy(newBuff, recvBuff + qDataSize, currLen - qDataSize);
						recvBuff = newBuff;
					}
					g_queue_push_tail(client->ch[MUSED_CHANNEL_DATA].queue, qData);
					g_cond_signal(&client->ch[MUSED_CHANNEL_DATA].cond);

					currLen = currLen - qDataSize;
					if (!currLen)
						break;
				}
				if (!currLen) {
					recvBuff = NULL;
				} else if (allocSize < MM_MSG_MAX_LENGTH + currLen) {
					allocSize = MM_MSG_MAX_LENGTH + currLen;
					recvBuff = g_renew(char, recvBuff, allocSize);
				}
			} else {
				intptr_t client_addr = 0;
				if (mmsvc_core_msg_json_deserialize_type("client_addr",
							recvBuff, &client_addr, NULL, MUSED_TYPE_POINTER)) {
					client = (Client) client_addr;
					if (client) {
						client->ch[MUSED_CHANNEL_DATA].p_gthread = g_thread_self();
					}
				}
				MMSVC_FREE(recvBuff);
				recvBuff = NULL;
				currLen = 0;
			}
		}
	}

	MMSVC_FREE(recvBuff);

	LOGD("Leave");
	return NULL;
}

static RecvData_t *_mmsvc_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize)
{
	int qDataSize;
	RecvData_t *qData = (RecvData_t *)*recvBuff;
	g_return_if_fail(recvBuff);

	if (qData->header.marker != MUSED_DATA_HEAD) {
		LOGE("Invalid data header");
		return NULL;
	}
	qDataSize = qData->header.size + sizeof(RecvDataHead_t);
	if (qDataSize > recvSize) {
		LOGD("not complated recv");
		if (qDataSize > *allocSize) {
			LOGD("Realloc %d -> %d", *allocSize, qDataSize);
			*allocSize = qDataSize;
			*recvBuff = g_renew(char, *recvBuff, *allocSize);
		}
		return NULL;
	}

	return qData;
}

gboolean mmsvc_core_ipc_job_function(mmsvc_core_workqueue_job_t *job)
{
	LOGD("Enter");
	Client client = NULL;

	g_return_val_if_fail(job != NULL, FALSE);

	client = (Client) job->user_data;
	g_return_val_if_fail(client != NULL, FALSE);

	LOGD("[%p] client->fd : %d", client, client->ch[MUSED_CHANNEL_MSG].fd);

	client->ch[MUSED_CHANNEL_MSG].p_gthread = g_thread_new(NULL, _mmsvc_core_ipc_dispatch_worker, (gpointer)client);
	g_return_val_if_fail(client->ch[MUSED_CHANNEL_MSG].p_gthread != NULL, FALSE);

	MMSVC_FREE(job);

	LOGD("Leave");
	return TRUE;
}

gboolean mmsvc_core_ipc_data_job_function(mmsvc_core_workqueue_job_t *job)
{
	LOGD("Enter");
	intptr_t fd;

	g_return_val_if_fail(job != NULL, FALSE);

	fd = (intptr_t) job->user_data;
	g_return_val_if_fail(fd > 0, FALSE);

	LOGD("data channel fd : %d", fd);

	g_thread_new(NULL, _mmsvc_core_ipc_data_worker, (gpointer)fd);

	MMSVC_FREE(job);

	LOGD("Leave");
	return TRUE;
}

int mmsvc_core_ipc_send_msg(int sock_fd, const char *msg)
{
	int ret = -1;

	g_return_val_if_fail(msg != NULL, ret);

	if ((ret = send(sock_fd, msg, strlen(msg), 0)) < 0)
		LOGE("send msg failed");

	return ret;
}

int mmsvc_core_ipc_recv_msg(int sock_fd, char *msg)
{
	int ret = -1;

	g_return_val_if_fail(msg != NULL, ret);

	if ((ret = recv(sock_fd, msg, MM_MSG_MAX_LENGTH, 0)) < 0)
		LOGE("fail to receive msg (%d)", ret);

	return ret;
}

int mmsvc_core_ipc_push_data(int sock_fd, const char *data, int size, int data_id)
{
	int ret = -1;
	RecvDataHead_t header;
	g_return_val_if_fail(data != NULL, ret);

	header.marker = MUSED_DATA_HEAD;
	header.id = data_id;
	header.size = size;

	if ((ret = send(sock_fd, &header, sizeof(RecvDataHead_t), 0)) < 0)
		LOGE("fail to send msg");
	if ((ret += send(sock_fd, data, size, 0)) < 0)
		LOGE("fail to send msg");

	return ret;
}

void mmsvc_core_ipc_delete_data(char *data)
{
	RecvData_t *qData;
	g_return_if_fail(data);

	qData = (RecvData_t *)(data - sizeof(RecvDataHead_t));
	if (qData && qData->header.marker == MUSED_DATA_HEAD)
		MMSVC_FREE(qData);
}

char *mmsvc_core_ipc_get_data(Client client)
{
	RecvData_t *qData;
	char *rawData;
	channel_info *ch;
	gint64 end_time = g_get_monotonic_time() + 100 * G_TIME_SPAN_MILLISECOND;
	g_return_val_if_fail(client, NULL);
	ch = &client->ch[MUSED_CHANNEL_DATA];
	g_return_val_if_fail(ch->queue, NULL);

	g_mutex_lock(&ch->mutex);
	if (g_queue_is_empty(ch->queue))
		g_cond_wait_until(&ch->cond, &ch->mutex, end_time);
	g_mutex_unlock(&ch->mutex);

	qData = g_queue_pop_head(ch->queue);
	if (qData) {
		rawData = (char *)qData + sizeof(RecvDataHead_t);
		return rawData;
	}

	return NULL;
}

intptr_t mmsvc_core_ipc_get_handle(Client client)
{
	g_return_val_if_fail(client, NULL);
	return client->handle;
}
