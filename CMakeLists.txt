
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
SET(fw_name "mused")

PROJECT(${fw_name})

SET(SRCS
       src/muse_core.c
       src/muse_core_config.c
       src/muse_core_ipc.c
       src/muse_core_log.c
       src/muse_core_module.c
       src/muse_core_msg_json.c
       src/muse_core_security.c
       src/muse_core_tool.c
       src/muse_core_workqueue.c
       )
SET(SRC-SERVER
       src/muse_core_server.c
       )

SET(CMAKE_INSTALL_PREFIX /usr)
SET(PREFIX ${CMAKE_INSTALL_PREFIX})

SET(BINDIR "${PREFIX}/bin")
SET(INC_DIR include)
INCLUDE_DIRECTORIES(${INC_DIR})

SET(dependents "dlog mm-common json-c glib-2.0 capi-base-common gmodule-2.0 iniparser gstreamer-1.0 libtbm cynara-client cynara-creds-socket cynara-session")
SET(pc_dependents "dlog mm-common capi-base-common libtbm")

INCLUDE(FindPkgConfig)
pkg_check_modules(${fw_name} REQUIRED ${dependents})
FOREACH(flag ${${fw_name}_CFLAGS})
    SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -fPIE -Werror -Wextra -Wno-array-bounds -Wno-empty-body -Wno-ignored-qualifiers -Wno-unused-parameter -Wshadow -Wwrite-strings -Wswitch-default -Wno-unused-but-set-parameter -Wno-unused-but-set-variable")
SET(CMAKE_C_FLAGS_DEBUG "-O0 -g")

IF("${ARCH}" STREQUAL "arm")
    ADD_DEFINITIONS("-DTARGET")
ENDIF("${ARCH}" STREQUAL "arm")

ADD_DEFINITIONS("-DPREFIX=\"${CMAKE_INSTALL_PREFIX}\"")
ADD_DEFINITIONS("-DTIZEN_DEBUG")

SET(CMAKE_EXE_LINKER_FLAGS "-Wl,--as-needed -pie")

aux_source_directory(src SOURCES)
ADD_LIBRARY(${fw_name} SHARED ${SRCS})

TARGET_LINK_LIBRARIES(${fw_name} ${${fw_name}_LDFLAGS})

SET_TARGET_PROPERTIES(${fw_name}
     PROPERTIES
     VERSION ${FULLVER}
     SOVERSION ${MAJORVER}
     CLEAN_DIRECT_OUTPUT 1
)

ADD_EXECUTABLE(muse-server ${SRC-SERVER})
TARGET_LINK_LIBRARIES(muse-server ${pkgs_LDFLAGS} ${fw_name} ${CMAKE_DL_LIBS})
INSTALL(TARGETS muse-server DESTINATION ${BINDIR})

INSTALL(TARGETS ${fw_name} DESTINATION ${LIBDIR})
INSTALL(
        DIRECTORY ${INC_DIR}/ DESTINATION include/media
        FILES_MATCHING
        PATTERN "*_private.h" EXCLUDE
        PATTERN "${INC_DIR}/*.h"
        )

SET(PC_NAME ${fw_name})
SET(PC_REQUIRED ${pc_dependents})
SET(PC_LDFLAGS -l${fw_name})
SET(PC_CFLAGS -I\${includedir}/media)

CONFIGURE_FILE(
    ${fw_name}.pc.in
    ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc
    ${CMAKE_CURRENT_SOURCE_DIR}/config/${fw_name}.conf
    @ONLY
)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/${fw_name}.pc DESTINATION ${LIBDIR}/pkgconfig)
INSTALL(FILES ${CMAKE_CURRENT_SOURCE_DIR}/config/${fw_name}.conf DESTINATION /usr/share/${fw_name})

IF(UNIX)

ADD_CUSTOM_TARGET (distclean @echo cleaning for source distribution)
ADD_CUSTOM_COMMAND(
        DEPENDS clean
        COMMENT "distribution clean"
        COMMAND find
        ARGS    .
        -not -name config.cmake -and \(
        -name tester.c -or
        -name Testing -or
        -name CMakeFiles -or
        -name cmake.depends -or
        -name cmake.check_depends -or
        -name CMakeCache.txt -or
        -name cmake.check_cache -or
        -name *.cmake -or
        -name Makefile -or
        -name core -or
        -name core.* -or
        -name gmon.out -or
        -name install_manifest.txt -or
        -name *.pc -or
        -name *~ \)
        | grep -v TC | xargs rm -rf
        TARGET  distclean
        VERBATIM
)

ENDIF(UNIX)

