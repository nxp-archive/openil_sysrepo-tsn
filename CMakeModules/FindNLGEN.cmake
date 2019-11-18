#  NLGEN_FOUND - System has libnl
#  NLGEN_INCLUDE_DIRS - The libnl include directories
#  NLGEN_LIBRARIES - The libraries needed to use libnl
#  NLGEN_DEFINITIONS - Compiler switches required for using libnl

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
    pkg_check_modules(PC_NLGEN libnl-genl-3.0)
    set(NLGEN_DEFINITIONS ${PC_NLGEN_CFLAGS_OTHER})
endif()

find_path(NLGEN_INCLUDE_DIR linux/genetlink.h
          HINTS ${PC_NLGEN_INCLUDEDIR} ${PC_NLGEN_INCLUDE_DIRS}
          PATH_SUFFIXES linux)

find_library(NLGEN_LIBRARY NAMES nl-genl-3
             HINTS ${PC_NLGEN_LIBDIR} ${PC_NLGEN_LIBRARY_DIRS})

set(NLGEN_LIBRARIES ${NLGEN_LIBRARY} )
set(NLGEN_INCLUDE_DIRS ${NLGEN_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(libnl-genl-3  DEFAULT_MSG
                                  NLGEN_LIBRARY NLGEN_INCLUDE_DIR)

mark_as_advanced(NLGEN_INCLUDE_DIR NLGEN_LIBRARY)
