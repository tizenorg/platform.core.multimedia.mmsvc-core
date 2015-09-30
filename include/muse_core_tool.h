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
#ifndef __MUSE_CORE_TOOL_H__
#define __MUSE_CORE_TOOL_H__

#ifdef _cplusplus
extern "C" {
#endif

void muse_core_tool_parse_params(int argc, char **argv);
void muse_core_tool_recursive_rmdir(const char *path);

#ifdef _cplusplus
}
#endif

#endif	/*__MUSE_CORE_TOOL_H__*/
