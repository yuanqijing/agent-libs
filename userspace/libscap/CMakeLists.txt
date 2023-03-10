#
# Copyright (C) 2021 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
include_directories(../../common)

option(USE_BUNDLED_DEPS "Enable bundled dependencies instead of using the system ones" ON)

include(ExternalProject)

if(WIN32 OR NOT MINIMAL_BUILD)
	include(zlib)
endif()

add_definitions(-DPLATFORM_NAME="${CMAKE_SYSTEM_NAME}")

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	if(CMAKE_BUILD_TYPE STREQUAL "Debug")
		set(KBUILD_FLAGS "${SYSDIG_DEBUG_FLAGS}")
	endif()

    if(NOT DEFINED PROBE_VERSION)
        set(PROBE_VERSION "${SYSDIG_VERSION}")
    endif()
    if(NOT DEFINED PROBE_NAME)
        set(PROBE_NAME "kindling-falcolib-probe")
    endif()

    if(NOT DEFINED PROBE_DEVICE_NAME)
        set(PROBE_DEVICE_NAME "kindling-falcolib")
    endif()
endif()

if(CYGWIN)
include_directories("${WIN_HAL_INCLUDE}")
endif()

list(APPEND targetfiles
	scap.c
	scap_event.c
	scap_fds.c
	scap_iflist.c
	scap_savefile.c
	scap_procs.c
	scap_userlist.c
	syscall_info_table.c
	../../driver/dynamic_params_table.c
	../../driver/event_table.c
	../../driver/flags_table.c)

if(NOT APPLE)
	list(APPEND targetfiles
		scap_udig.c)
endif()


if(CMAKE_SYSTEM_NAME MATCHES "Linux")
	list(APPEND targetfiles
		scap_bpf.c
		../../driver/syscall_table.c
		../../driver/fillers_table.c)

    include_directories(${PROJECT_BINARY_DIR}/driver/src)
endif()

if(CYGWIN OR WIN32)
	list(APPEND targetfiles
		windows_hal.c)
endif()

add_library(scap STATIC
	${targetfiles})

if(USE_BUNDLED_ZLIB AND NOT MINIMAL_BUILD)
	add_dependencies(scap zlib)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
	target_link_libraries(scap
		socket nsl)
elseif (CMAKE_SYSTEM_NAME MATCHES "Linux")
	target_link_libraries(scap
		elf
		rt)
elseif (WIN32)
	target_link_libraries(scap
		Ws2_32.lib)
elseif (CYGWIN)
	target_link_libraries(scap
		/lib/w32api/libpsapi.a
		${WIN_HAL_LIB}/dragent_win_hal.lib)
endif()

if(NOT MINIMAL_BUILD)
target_link_libraries(scap
	"${ZLIB_LIB}")
endif()

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    add_subdirectory(../../driver ${PROJECT_BINARY_DIR}/driver)

    option(BUILD_LIBSCAP_EXAMPLES "Build libscap examples" ON)

    if (BUILD_LIBSCAP_EXAMPLES)
        add_subdirectory(examples/01-open)
        add_subdirectory(examples/02-validatebuffer)
    endif()

	include(FindMakedev)
endif()
