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

static mmsvc_core_ipc_t *g_mused_ipc;

static void _mmsvc_core_ipc_client_cleanup(Module module);
static gpointer _mmsvc_core_ipc_dispatch_worker(gpointer data);
static gpointer _mmsvc_core_ipc_data_worker(gpointer data);
static RecvData_t *_mmsvc_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize);
static bool _mmsvc_core_ipc_init_bufmgr(void);
static void _mmsvc_core_ipc_deinit_bufmgr(void);
static void _mmsvc_core_ipc_init_instance(void (*deinit)(void));

static void _mmsvc_core_ipc_client_cleanup(Module module)
{
	g_return_if_fail(module != NULL);

	g_queue_free(module->ch[MUSED_CHANNEL_DATA].queue);
	module->ch[MUSED_CHANNEL_DATA].queue = NULL;
	g_cond_broadcast(&module->ch[MUSED_CHANNEL_DATA].cond);
	g_thread_join(module->ch[MUSED_CHANNEL_DATA].p_gthread);
	g_mutex_clear(&module->ch[MUSED_CHANNEL_DATA].mutex);
	g_cond_clear(&module->ch[MUSED_CHANNEL_DATA].cond);
	LOGD("worker exit");
	mmsvc_core_worker_exit(module);
}

static gpointer _mmsvc_core_ipc_dispatch_worker(gpointer data)
{
	int len, parse_len, cmd, disp_api;
	Module module = NULL;
	mused_msg_parse_err_e err = MUSED_MSG_PARSE_ERROR_NONE;
	g_return_val_if_fail(data != NULL, NULL);

	module = (Module)data;
	g_return_val_if_fail(module != NULL, NULL);

	while (1) {
		memset(module->recvMsg, 0x00, sizeof(module->recvMsg));
		len = mmsvc_core_ipc_recv_msg(module->ch[MUSED_CHANNEL_MSG].fd, module->recvMsg);
		if (len <= 0) {
			LOGE("recv : %s (%d)", strerror(errno), errno);
			mmsvc_core_cmd_dispatch(module, MUSED_DOMAIN_EVENT_SHUTDOWN);
			_mmsvc_core_ipc_client_cleanup(module);
		} else {
			parse_len = len;
			LOGD("Message In");
			cmd = 0;
			disp_api = 0;
			module->msg_offset = 0;

			mmsvc_core_log_get_instance()->log(module->recvMsg);

			while (module->msg_offset < len) {
				if (mmsvc_core_msg_json_deserialize_len("api", module->recvMsg + module->msg_offset, &parse_len, &cmd, &err, MUSED_TYPE_INT)) {
					switch (cmd) {
					case API_CREATE:
						if (mmsvc_core_msg_json_deserialize_len("client", module->recvMsg + module->msg_offset, &parse_len, &disp_api, &err, MUSED_TYPE_INT)) {
							module->disp_api = disp_api;
							module->ch[MUSED_CHANNEL_MSG].dll_handle = mmsvc_core_module_load(disp_api);
							module->ch[MUSED_CHANNEL_DATA].queue = g_queue_new();
							g_mutex_init(&module->ch[MUSED_CHANNEL_DATA].mutex);
							g_cond_init(&module->ch[MUSED_CHANNEL_DATA].cond);
							LOGD("client fd: %d module: %p",
									module->ch[MUSED_CHANNEL_MSG].fd,
									module->ch[MUSED_CHANNEL_MSG].dll_handle);
							mmsvc_core_module_dll_symbol_dispatch(cmd, module);
							break;
						}
					case API_DESTROY:
						LOGD("DESTROY");
						mmsvc_core_module_dll_symbol_dispatch(cmd, module);
						_mmsvc_core_ipc_client_cleanup(module);
						break;
					default:
						LOGD("[default] module's dll_handle: %p", module->ch[MUSED_CHANNEL_MSG].dll_handle);
						mmsvc_core_module_dll_symbol_dispatch(cmd, module);
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

static gpointer _mmsvc_core_ipc_data_worker(gpointer data)
{
	int recvLen = 0;
	int currLen = 0;
	intptr_t fd = (intptr_t) data;
	Module module = NULL;
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
			if (module) {
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
					g_queue_push_tail(module->ch[MUSED_CHANNEL_DATA].queue, qData);
					g_cond_signal(&module->ch[MUSED_CHANNEL_DATA].cond);

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
					module = (Module) client_addr;
					if (module)
						module->ch[MUSED_CHANNEL_DATA].p_gthread = g_thread_self();
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

static bool _mmsvc_core_ipc_init_bufmgr(void)
{
	LOGD("Enter");
	g_return_if_fail(g_mused_ipc != NULL);

	g_mused_ipc->bufmgr = tbm_bufmgr_init(-1);
	if(g_mused_ipc->bufmgr == NULL) {
		LOGE("Error - tbm_bufmgr_init");
		return FALSE;
	}
	LOGD("bufmgr: 0x%x", g_mused_ipc->bufmgr);

	LOGD("Leave");
	return TRUE;
}

static void _mmsvc_core_ipc_deinit_bufmgr(void)
{
	LOGD("Enter");
	g_return_if_fail(g_mused_ipc->bufmgr);

	tbm_bufmgr_deinit(g_mused_ipc->bufmgr);
	LOGD("Leave");
}

static void _mmsvc_core_ipc_init_instance(void (*deinit)(void))
{
	g_return_if_fail(deinit != NULL);
	g_return_if_fail(g_mused_ipc == NULL);

	g_mused_ipc = calloc(1, sizeof(*g_mused_ipc));
	g_return_if_fail(g_mused_ipc != NULL);
	g_return_if_fail(_mmsvc_core_ipc_init_bufmgr() == TRUE);

	g_mused_ipc->deinit = deinit;
}

int mmsvc_core_ipc_get_client_from_job(mmsvc_core_workqueue_job_t *job)
{
	LOGD("Enter");
	Module module = NULL;

	g_return_val_if_fail(job != NULL, MM_ERROR_INVALID_ARGUMENT);

	module = (Module) job->user_data;
	g_return_val_if_fail(module != NULL, MM_ERROR_INVALID_ARGUMENT);

	LOGD("Leave");
	return module->disp_api;
}

gboolean mmsvc_core_ipc_job_function(mmsvc_core_workqueue_job_t *job)
{
	LOGD("Enter");
	Module module = NULL;

	g_return_val_if_fail(job != NULL, FALSE);

	module = (Module) job->user_data;
	g_return_val_if_fail(module != NULL, FALSE);

	LOGD("[%p] client->fd : %d", module, module->ch[MUSED_CHANNEL_MSG].fd);

	module->ch[MUSED_CHANNEL_MSG].p_gthread = g_thread_new(NULL, _mmsvc_core_ipc_dispatch_worker, (gpointer)module);
	g_return_val_if_fail(module->ch[MUSED_CHANNEL_MSG].p_gthread != NULL, FALSE);

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
	int ret = MM_ERROR_NONE;

	g_return_val_if_fail(msg != NULL, MM_ERROR_INVALID_ARGUMENT);

	if ((ret = send(sock_fd, msg, strlen(msg), 0)) < 0)
		LOGE("send msg failed");

	return ret;
}

int mmsvc_core_ipc_recv_msg(int sock_fd, char *msg)
{
	int ret = MM_ERROR_NONE;

	g_return_val_if_fail(msg != NULL, MM_ERROR_INVALID_ARGUMENT);

	if ((ret = recv(sock_fd, msg, MM_MSG_MAX_LENGTH, 0)) < 0)
		LOGE("fail to receive msg (%s)", strerror(errno));

	return ret;
}

int mmsvc_core_ipc_push_data(int sock_fd, const char *data, int size, int data_id)
{
	int ret = MM_ERROR_NONE;

	RecvDataHead_t header;
	g_return_val_if_fail(data != NULL, MM_ERROR_INVALID_ARGUMENT);

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

char *mmsvc_core_ipc_get_data(Module module)
{
	RecvData_t *qData;
	char *rawData;
	channel_info *ch;
	gint64 end_time = g_get_monotonic_time() + 100 * G_TIME_SPAN_MILLISECOND;
	g_return_val_if_fail(module, NULL);
	ch = &module->ch[MUSED_CHANNEL_DATA];
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

intptr_t mmsvc_core_ipc_get_handle(Module module)
{
	g_return_val_if_fail(module, NULL);
	g_return_val_if_fail(module->handle, NULL);
	return module->handle;
}

int mmsvc_core_ipc_set_handle(Module module, intptr_t handle)
{
	g_return_val_if_fail(module, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(handle, MM_ERROR_INVALID_HANDLE);

	module->handle = handle;
	return MM_ERROR_NONE;
}

int mmsvc_core_ipc_get_bufmgr(tbm_bufmgr *bufmgr)
{
	LOGD("Enter");
	g_return_val_if_fail(bufmgr, MM_ERROR_INVALID_ARGUMENT);
	g_return_val_if_fail(g_mused_ipc->bufmgr, MM_ERROR_INVALID_ARGUMENT);

	LOGD("bufmgr: 0x%x", g_mused_ipc->bufmgr);
	*bufmgr = g_mused_ipc->bufmgr;
	LOGD("Leave");
	return MM_ERROR_NONE;
}

mmsvc_core_ipc_t *mmsvc_core_ipc_get_instance(void)
{
	if (g_mused_ipc == NULL)
		_mmsvc_core_ipc_init_instance(_mmsvc_core_ipc_deinit_bufmgr);

	return g_mused_ipc;
}

void mmsvc_core_ipc_init(void)
{
	LOGD("Enter");

	if (g_mused_ipc == NULL)
		_mmsvc_core_ipc_init_instance(_mmsvc_core_ipc_deinit_bufmgr);

	LOGD("Leave");
}