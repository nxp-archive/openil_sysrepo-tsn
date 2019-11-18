#  NL_FOUND - System has libnl
#  NL_INCLUDE_DIRS - The libnl include directories
#  NL_LIBRARIES - The libraries needed to use libnl
#  NL_DEFINITIONS - Compiler switches required for using libnl

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_NL libnl-3.0)
    set(NL_DEFINITIONS ${PC_NL_CFLAGS_OTHER})
endif()

find_path(NL_INCLUDE_DIR netlink/netlink.h
          HINTS ${PC_NL_INCLUDEDIR} ${PC_NL_INCLUDE_DIRS}
          PATH_SUFFIXES netlink)

find_library(NL_LIBRARY NAMES nl-3
             HINTS ${PC_NL_LIBDIR} ${PC_NL_LIBRARY_DIRS})

set(NL_LIBRARIES ${NL_LIBRARY} )
set(NL_INCLUDE_DIRS ${NL_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libnl-3  DEFAULT_MSG
                                  NL_LIBRARY NL_INCLUDE_DIR)

mark_as_advanced(NL_INCLUDE_DIR NL_LIBRARY)
