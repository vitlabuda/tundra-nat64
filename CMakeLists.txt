###########################
#      Basic options      #
###########################

cmake_minimum_required(VERSION 3.16)
project(tundra-nat64 LANGUAGES C)

set(EXECUTABLE "tundra-nat64")
file(GLOB SOURCES "src/*.c")
set(CONFIG_FILE "tundra-nat64.example.conf")
set(MANPAGE_PROGRAM "manpages/tundra-nat64.8")
set(MANPAGE_CONFIG "manpages/tundra-nat64.conf.5")

set(MESSAGE_BANNER "tundra-nat64")




#######################################
#      Flags & macro definitions      #
#######################################

# Source: https://airbus-seclab.github.io/c-compiler-security/
set(HARDENING_WARN_FLAGS "-Werror=implicit-function-declaration -Werror=shadow -Werror=strict-prototypes \
                          -Wdate-time -Walloca -Wvla -Wimplicit-fallthrough=3 -Wduplicated-cond -Wduplicated-branches \
                          -Wundef -Wswitch-default -Wswitch-enum -Wlogical-op -Wtrampolines -Wstack-protector \
                          -Wstack-usage=524288 -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security \
                          -Wformat-signedness -Wformat-nonliteral -Wfloat-equal -Wnull-dereference -Warray-bounds=2 \
                          -Wstringop-overflow=4 -Wshift-overflow=2 -Wstrict-overflow=2 -Wconversion -Wsign-conversion \
                          -Wint-conversion -Wfloat-conversion -Wcast-qual -Wcast-align=strict")
set(HARDENING_LINK_FLAGS "-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code")
set(HARDENING_OPT_FLAGS "-fstack-protector-strong -fstack-clash-protection")
set(HARDENING_MACRO_DEFS "_FORTIFY_SOURCE=2")

set(BASIC_FLAGS "-std=c11 -pthread -pie -fPIE")
set(WARN_FLAGS "-Wall -Wextra -Wpedantic ${HARDENING_WARN_FLAGS}")
set(LINK_FLAGS "${HARDENING_LINK_FLAGS}")
set(OPT_FLAGS "-O3 -flto ${HARDENING_OPT_FLAGS}")

# The 'AUTHOR_BUILD' environment variable enables some compiler flags which the author of this project uses for some
# of their builds. You should most probably ignore these flags and NOT define the environment variable.
if(DEFINED ENV{AUTHOR_BUILD})
    message(STATUS "[${MESSAGE_BANNER}] AUTHOR_BUILD is defined, enabling some special compiler flags!")

    if(DEFINED ENV{AUTHOR_BUILD_ARCH})
        set(MISC_FLAGS "-s -Werror -march=$ENV{AUTHOR_BUILD_ARCH}")
    else()
        set(MISC_FLAGS "-s -Werror")
    endif()
elseif(DEFINED ENV{CI_BUILD})
    message(STATUS "[${MESSAGE_BANNER}] CI_BUILD is defined, compiler warnings are now treated as errors!")

    set(MISC_FLAGS "-g -Werror")
else()
    set(MISC_FLAGS "-g")
endif()

set(ALL_FLAGS "${BASIC_FLAGS} ${WARN_FLAGS} ${LINK_FLAGS} ${OPT_FLAGS} ${MISC_FLAGS}")
set(ALL_MACRO_DEFS "${HARDENING_MACRO_DEFS}")

if(NOT DEFINED ENV{CFLAGS})
    message(STATUS "[${MESSAGE_BANNER}] CFLAGS not defined, using default flags.")

    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ALL_FLAGS}")
    add_compile_definitions("${ALL_MACRO_DEFS}")
endif()




#######################################
#      Version string definition      #
#######################################

set(VERSION_FILE "${CMAKE_SOURCE_DIR}/VERSION")
file(READ "${VERSION_FILE}" VERSION)
string(REGEX REPLACE "[ \t\r\n]" "" VERSION "${VERSION}")
add_compile_definitions("TUNDRA__VERSION_STRING=\"${VERSION}\"")




#######################################
#      Executable & installation      #
#######################################

add_executable(${EXECUTABLE} ${SOURCES})

include(GNUInstallDirs)
install(TARGETS "${EXECUTABLE}" DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(FILES "${CONFIG_FILE}" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/tundra-nat64")
install(FILES "${MANPAGE_PROGRAM}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man8")
install(FILES "${MANPAGE_CONFIG}" DESTINATION "${CMAKE_INSTALL_MANDIR}/man5")
