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

#include "muse_core.h"
#include "muse_core_private.h"
#include "muse_core_config.h"
#include "muse_core_internal.h"
#include "muse_core_log.h"
#include "muse_core_ipc.h"
#include "muse_core_msg_json.h"
#include "muse_core_module.h"

typedef struct muse_recv_data_head {
	int marker;
	int id;
	int size;
} muse_recv_data_head_t;

typedef struct muse_recv_data {
	muse_recv_data_head_t header;
	/* Dynamic allocated data area */
} muse_recv_data_t;

static muse_core_ipc_t *g_muse_core_ipc;

static void _muse_core_ipc_client_cleanup(muse_module_h module);
static gpointer _muse_core_ipc_dispatch_worker(gpointer data);
static gpointer _muse_core_ipc_data_worker(gpointer data);
static muse_recv_data_t *_muse_core_ipc_new_qdata(char **recvBuff, int recvSize, int *allocSize);
static bool _muse_core_ipc_init_bufmgr(void);
static void _muse_core_ipc_deinit_bufmgr(void);
static void _muse_core_ipc_init_instance(void (*deinit)(void));

static void _muse_core_ipc_client_cleanup(muse_module_h module)
{
	g_return_if_fail(module != NULL);

	muse_core_log_get_instance()->flush_msg();
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
	g_return_val_if_fail(data != NULL, NULL);

	module = (muse_module_h)data;
	g_return_val_if_fail(module != NULL, NULL);

	while (1) {
		memset(module->recvMsg, 0x00, sizeof(module->recvMsg));
		len = muse_core_ipc_recv_msg(module->ch[MUSE_CHANNEL_MSG].fd, module->recvMsg);
		if (len <= 0) {
			LOGE("recv : %s (%d)", strerror(errno), errno);
			muse_core_cmd_dispatch(module, MUSE_MODULE_EVENT_SHUTDOWN);
			_muse_core_ipc_client_cleanup(module);
		} else {
			parse_len = len;
			LOGD("Message In");
			cmd = 0;
			api_module = 0;
			module->msg_offset = 0;

			muse_core_log_get_instance()->log(module->recvMsg);

			while (module->msg_offset < len) {
				if (muse_core_msg_json_deserialize(MUSE_API, module->recvMsg + module->msg_offset, &parse_len, &cmd, &err, MUSE_TYPE_INT)) {
					switch (cmd) {
						module->disp_api = cmd;
					case API_CREATE:
						if (muse_core_msg_json_deserialize(MUSE_MODULE, module->recvMsg + module->msg_offset, &parse_len, &api_module, &err, MUSE_TYPE_INT)) {
							module->api_module = api_module;
							module->ch[MUSE_CHANNEL_MSG].dll_handle = muse_core_module_get_instance()->load(api_module);
							module->ch[MUSE_CHANNEL_DATA].queue = g_queue_new();
							g_mutex_init(&module->ch[MUSE_CHANNEL_DATA].mutex);
							g_cond_init(&module->ch[MUSE_CHANNEL_DATA].cond);
							LOGD("module fd: %d dll_handle: %p", module->ch[MUSE_CHANNEL_MSG].fd, module->ch[MUSE_CHANNEL_MSG].dll_handle);
							muse_core_module_get_instance()->dispatch(cmd, module);
							break;
						}
					case API_DESTROY:
						LOGD("DESTROY");
						muse_core_module_get_instance()->dispatch(cmd, module);
						_muse_core_ipc_client_cleanup(module);
						break;
					default:
						LOGD("[default] module's dll_handle: %p", module->ch[MUSE_CHANNEL_MSG].dll_handle);
						muse_core_module_get_instance()->dispatch(cmd, module);
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

	g_return_val_if_fail(fd > 0, NULL);

	while(1) {
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
		LOGD("buff %p, recvLen %d, currLen %d, allocSize %d",
				recvBuff, recvLen, currLen, allocSize);
		if (recvLen <= 0) {
			LOGE("recv : %s (%d)", strerror(errno), errno);
			break;
		} else {
			if (module) {
				muse_recv_data_t *qData;
				while ((qData = _muse_core_ipc_new_qdata(&recvBuff, currLen, &allocSize))
						!= NULL) {
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
				if (muse_core_msg_json_deserialize(MUSE_MODULE_ADDR,
							recvBuff, NULL, &module_addr, NULL, MUSE_TYPE_POINTER)) {
					module = (muse_module_h) module_addr;
					if (module)
						module->ch[MUSE_CHANNEL_DATA].p_gthread = g_thread_self();
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

static bool _muse_core_ipc_init_bufmgr(void)
{
	LOGD("Enter");
	g_return_val_if_fail(g_muse_core_ipc != NULL, FALSE);

	g_muse_core_ipc->bufmgr = tbm_bufmgr_init(-1);
	if(g_muse_core_ipc->bufmgr == NULL) {
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

static void _muse_core_ipc_init_instance(void (*deinit)(void))
{
	g_return_if_fail(deinit != NULL);
	g_return_if_fail(g_muse_core_ipc == NULL);

	g_muse_core_ipc = calloc(1, sizeof(*g_muse_core_ipc));
	g_return_if_fail(g_muse_core_ipc != NULL);
	g_return_if_fail(_muse_core_ipc_init_bufmgr() == TRUE);

	g_muse_core_ipc->deinit = deinit;
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

	g_return_val_if_fail(job != NULL, FALSE);

	module = (muse_module_h) job->user_data;
	g_return_val_if_fail(module != NULL, FALSE);

	LOGD("[%p] client's fd : %d", module, module->ch[MUSE_CHANNEL_MSG].fd);

	module->ch[MUSE_CHANNEL_MSG].p_gthread = g_thread_new(NULL, _muse_core_ipc_dispatch_worker, (gpointer)module);
	g_return_val_if_fail(module->ch[MUSE_CHANNEL_MSG].p_gthread != NULL, FALSE);

	MUSE_FREE(job);

	LOGD("Leave");
	return TRUE;
}

gboolean muse_core_ipc_data_job_function(muse_core_workqueue_job_t *job)
{
	LOGD("Enter");
	intptr_t fd;

	g_return_val_if_fail(job != NULL, FALSE);

	fd = (intptr_t) job->user_data;
	g_return_val_if_fail(fd > 0, FALSE);

	LOGD("data channel fd : %d", fd);

	g_thread_new(NULL, _muse_core_ipc_data_worker, (gpointer)fd);

	MUSE_FREE(job);

	LOGD("Leave");
	return TRUE;
}

int muse_core_ipc_send_msg(int sock_fd, const char *msg)
{
	int ret = MM_ERROR_NONE;

	g_return_val_if_fail(msg != NULL, MM_ERROR_INVALID_ARGUMENT);

	if ((ret = send(sock_fd, msg, strlen(msg), 0)) < 0)
		LOGE("send msg failed");

	return ret;
}

int muse_core_ipc_recv_msg(int sock_fd, char *msg)
{
	int ret = MM_ERROR_NONE;

	g_return_val_if_fail(msg != NULL, MM_ERROR_INVALID_ARGUMENT);

	if ((ret = recv(sock_fd, msg, MUSE_MSG_MAX_LENGTH, 0)) < 0)
		LOGE("fail to receive msg (%s)", strerror(errno));

	return ret;
}

int muse_core_ipc_push_data(int sock_fd, const char *data, int size, int data_id)
{
	int ret = MM_ERROR_NONE;

	muse_recv_data_head_t header;
	g_return_val_if_fail(data != NULL, MM_ERROR_INVALID_ARGUMENT);

	header.marker = MUSE_DATA_HEAD;
	header.id = data_id;
	header.size = size;

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
		_muse_core_ipc_init_instance(_muse_core_ipc_deinit_bufmgr);

	return g_muse_core_ipc;
}

void muse_core_ipc_init(void)
{
	LOGD("Enter");

	if (g_muse_core_ipc == NULL)
		_muse_core_ipc_init_instance(_muse_core_ipc_deinit_bufmgr);

	LOGD("Leave");
}
