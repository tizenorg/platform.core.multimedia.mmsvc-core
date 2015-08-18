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
#include "mmsvc_core_tool.h"
#include <fts.h>

#define VERSION "0.0.1"

static int _mmsvc_core_tool_getopt(int argc, char **argv, const char *opts);

int mmsvc_tool_optind = 1;
int mmsvc_tool_optopt;
char *mmsvc_tool_optarg;

static const char *pid_file = NULL;
static const char *out_file = NULL;
static const char *err_file = NULL;
static const char *lock_file = NULL;
static bool be_verbose = FALSE;
static const char *user  = NULL;
static char **mmsvc_cmd = NULL;
static const char *cwd = "/";
static int append = 0;

static int _mmsvc_core_tool_getopt(int argc, char **argv, const char *opts)
{
	static int si = 1;
	register int ri;
	register char *cp;

	if (si == 1) {
		if (mmsvc_tool_optind >= argc ||argv[mmsvc_tool_optind][0] != '-' || argv[mmsvc_tool_optind][1] == '\0') {
			return(EOF);
		} else if (strcmp(argv[mmsvc_tool_optind], "--") == 0) {
			mmsvc_tool_optind++;
			return(EOF);
		}
	}
	mmsvc_tool_optopt = ri = argv[mmsvc_tool_optind][si];
	if (ri == ':' || (cp=strchr(opts, ri)) == NULL) {
		if (argv[mmsvc_tool_optind][++si] == '\0') {
			mmsvc_tool_optind++;
			si = 1;
		}
		return('?');
	}
	if (*++cp == ':') {
		if (argv[mmsvc_tool_optind][si+1] != '\0') {
			mmsvc_tool_optarg = &argv[mmsvc_tool_optind++][si+1];
			LOGD("%s", mmsvc_tool_optarg);
		} else if (++mmsvc_tool_optind >= argc) {
			LOGE(": option requires an argument - %c", ri);
			si = 1;
			return('?');
		} else {
			mmsvc_tool_optarg = argv[mmsvc_tool_optind++];
			LOGD("%s", mmsvc_tool_optarg);
		}
		si = 1;
	} else {
		if (argv[mmsvc_tool_optind][++si] == '\0') {
			si = 1;
			mmsvc_tool_optind++;
		}
		mmsvc_tool_optarg = NULL;
	}
	LOGD("mmsvc_tool_optind: %d", mmsvc_tool_optind);
	return(ri);
}

/**
 * Parse the command-line parameters, setting the various globals that are affected by them.
 *
 * Parameters:
 *     argc - argument count, as passed to main()
 *     argv - argument vector, as passed to main()
 */
void mmsvc_core_tool_parse_params(int argc, char **argv)
{
	int opt;
	int argsLeft;

	LOGD("Enter");
	opterr = 0;

	while ((opt = _mmsvc_core_tool_getopt(argc, argv, "ac:u:p:vo:e:l:")) != -1) {
		switch (opt) {
		case 'a':
			append = 1;
			break;

		case 'c':
			cwd = mmsvc_tool_optarg;
			break;

		case 'p':

			pid_file = mmsvc_tool_optarg;
			break;

		case 'v':
			be_verbose = TRUE;
			break;

		case 'u':
			user = mmsvc_tool_optarg;
			break;

		case 'o':
			out_file = mmsvc_tool_optarg;
			LOGD("out file: %s", out_file);
			break;

		case 'e':
			err_file = mmsvc_tool_optarg;
			break;

		case 'l':
			lock_file = mmsvc_tool_optarg;
			break;

		default:
			break;
		}
	}

	LOGD("mmsvc_tool_optind: %d", mmsvc_tool_optind);
	argsLeft = argc - mmsvc_tool_optind;
	LOGD("argsLeft : %d", argsLeft);

	mmsvc_cmd = &argv[mmsvc_tool_optind];
	LOGD("cmd: %s", *mmsvc_cmd);
	LOGD("Leave");
	return;
}

void mmsvc_core_tool_recursive_rmdir(const char *path)
{
	FTS *fts;
	FTSENT *ftsent;

	g_return_if_fail (path != NULL);

	char *const paths[] = { (char *)path, NULL };

	/* This means there can't be any autofs mounts yet, so this is the first time we're being run since a reboot. Clean out any stuff left in /Network from the reboot. */
	fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, NULL);
	if (fts != NULL) {
		while ((ftsent = fts_read(fts)) != NULL) {
			/* We only remove directories - if there are files, we assume they're there for a purpose.
			* FTS_DP removed the directories visited in post-order (left, right, root).*/
			if (ftsent->fts_info == FTS_DP && ftsent->fts_level >= FTS_ROOTLEVEL)
				rmdir(ftsent->fts_accpath); /* access path */
		}
		fts_close(fts);
	} else {
		LOGE("Error - null fts");
		return;
	}
}

long mmsvc_core_tool_get_file_size(int fd)
{
	return lseek(fd, (off_t)0, SEEK_CUR);
}
