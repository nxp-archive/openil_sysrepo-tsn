#  TSN_FOUND - System has libtsn
#  TSN_INCLUDE_DIRS - The libtsn include directories
#  TSN_LIBRARIES - The libraries needed to use libtsn
#  TSN_DEFINITIONS - Compiler switches required for using libtsn

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_TSN libtsn)
    set(TSN_DEFINITIONS ${PC_TSN_CFLAGS_OTHER})
endif()

find_path(TSN_INCLUDE_DIR tsn/genl_tsn.h
          HINTS ${PC_TSN_INCLUDEDIR} ${PC_TSN_INCLUDE_DIRS}
          PATH_SUFFIXES tsn)

find_library(TSN_LIBRARY NAMES tsn
             HINTS ${PC_TSN_LIBDIR} ${PC_TSN_LIBRARY_DIRS})

set(TSN_LIBRARIES ${TSN_LIBRARY} )
set(TSN_INCLUDE_DIRS ${TSN_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(tsn  DEFAULT_MSG
                                  TSN_LIBRARY TSN_INCLUDE_DIR)

mark_as_advanced(TSN_INCLUDE_DIR TSN_LIBRARY)
