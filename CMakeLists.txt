cmake_minimum_required(VERSION 2.8.12)
project(sysrepo-tsn)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wpedantic")

# include custom Modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/CMakeModules/")

include_directories("${PROJECT_SOURCE_DIR}/inc")

# dependencies - cjson
find_package(CJSON REQUIRED)
include_directories(${CJSON_INCLUDE_DIRS})
set(LIBS ${LIBS} ${CJSON_LIBRARIES})

# dependencies - nl
find_package(NL REQUIRED)
include_directories(${NL_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NL_LIBRARIES})

# dependencies - gen-nl
find_package(NLGEN REQUIRED)
include_directories(${NLGEN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${NLGEN_LIBRARIES})

# dependencies - libtsn
find_package(TSN REQUIRED)
include_directories(${TSN_INCLUDE_DIRS})
set(LIBS ${LIBS} ${TSN_LIBRARIES})

# dependencies - sysrepo
find_package(SYSREPO REQUIRED)
include_directories(${SYSREPO_INCLUDE_DIRS})
set(LIBS ${LIBS} ${SYSREPO_LIBRARIES})

# dependencies - pthread
find_package(Threads)
set(LIBS ${LIBS} ${CMAKE_THREAD_LIBS_INIT})

set(SOURCES
		src/main.c
		src/common.c
		src/qbv.c
		src/qbu.c
		src/cb_streamid.c
		src/qci.c
		src/qci_sf.c
		src/file_mon.c)

find_package(PkgConfig)

# get sysrepo plugins directory
if (NOT SR_PLUGINS_DIR)
    if (PKG_CONFIG_FOUND)
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE} "--variable=SR_PLUGINS_DIR" "libsysrepo" OUTPUT_VARIABLE SR_PLUGINS_DIR)
        string(STRIP ${SR_PLUGINS_DIR} SR_PLUGINS_DIR)
    endif()
endif()
if (NOT SR_PLUGINS_DIR)
    message(FATAL_ERROR "Cannot get sysrepo plugins directory due to missing pkg-config, set SR_PLUGINS_DIR manually.")
endif()

# find programs
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

if (NOT SYSREPOCFG_EXECUTABLE)
    find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
# find programs
if (NOT SYSREPOCTL_EXECUTABLE)
    find_program(SYSREPOCTL_EXECUTABLE sysrepoctl)
endif()
if (NOT SYSREPOCTL_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepoctl, set SYSREPOCTL_EXECUTABLE manually.")
endif()

if (NOT SYSREPOCFG_EXECUTABLE)
    find_program(SYSREPOCFG_EXECUTABLE sysrepocfg)
endif()
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

if (NOT CHMOD_EXECUTABLE)
    find_program(CHMOD_EXECUTABLE chmod)
endif()
if (NOT CHMOD_EXECUTABLE)
    message(FATAL_ERROR "Unable to find chmod, set CHMOD_EXECUTABLE manually.")
endif()

endif()
if (NOT SYSREPOCFG_EXECUTABLE)
    message(FATAL_ERROR "Unable to find sysrepocfg, set SYSREPOCFG_EXECUTABLE manually.")
endif()

if (NOT CHMOD_EXECUTABLE)
    find_program(CHMOD_EXECUTABLE chmod)
endif()
if (NOT CHMOD_EXECUTABLE)
    message(FATAL_ERROR "Unable to find chmod, set CHMOD_EXECUTABLE manually.")
endif()

# Command line options to be passed to `sysrepoctl` when working with modules
# which should only be accessible by an administrator
if (NOT SYSREPOCTL_ROOT_PERMS)
    set(SYSREPOCTL_ROOT_PERMS "-o root:root -p 600")
endif()

install(CODE "
	set(ENV{SYSREPOCTL} ${SYSREPOCTL_EXECUTABLE})
	set(ENV{SYSREPOCTL_ROOT_PERMS} SYSREPOCTL_ROOT_PERMS)
	execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/scripts/model-install.sh)")

add_executable(${CMAKE_PROJECT_NAME} ${SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${LIBS})

install(TARGETS ${CMAKE_PROJECT_NAME} RUNTIME DESTINATION bin)
