#  SYSREPO_FOUND - System has libsysrepo
#  SYSREPO_INCLUDE_DIRS - The libsysrepo include directories
#  SYSREPO_LIBRARIES - The libraries needed to use libsysrepo
#  SYSREPO_DEFINITIONS - Compiler switches required for using libsysrepo

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_SYSREPO libsysrepo)
    set(SYSREPO_DEFINITIONS ${PC_SYSREPO_CFLAGS_OTHER})
endif()

find_path(SYSREPO_INCLUDE_DIR sysrepo.h
          HINTS ${PC_SYSREPO_INCLUDEDIR} ${PC_SYSREPO_INCLUDE_DIRS}
          PATH_SUFFIXES sysrepo)

find_library(SYSREPO_LIBRARY NAMES sysrepo
             HINTS ${PC_SYSREPO_LIBDIR} ${PC_SYSREPO_LIBRARY_DIRS})

set(SYSREPO_LIBRARIES ${SYSREPO_LIBRARY} )
set(SYSREPO_INCLUDE_DIRS ${SYSREPO_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(sysrepo  DEFAULT_MSG
                                  SYSREPO_LIBRARY SYSREPO_INCLUDE_DIR)

mark_as_advanced(SYSREPO_INCLUDE_DIR SYSREPO_LIBRARY)
