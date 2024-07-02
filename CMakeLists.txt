cmake_minimum_required(VERSION 3.16)
project(tundra-nat64 LANGUAGES C)

set(EXECUTABLE "tundra-nat64")
file(GLOB SOURCES "src/*.c")
set(CONFIG_FILE "tundra-nat64.example.conf")

set(HARDENING_WARN_FLAGS "-Walloca -Wvla -Wshadow -Wimplicit-fallthrough=3 -Wduplicated-cond -Wduplicated-branches \
                          -Wundef -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wlogical-op -Wtrampolines \
                          -Wstack-protector -Wstack-usage=524288 -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 \
                          -Wformat-signedness -Wformat-security -Wformat-nonliteral")
set(WARN_FLAGS "-Wall -Wextra -Wpedantic -Werror ${HARDENING_WARN_FLAGS}")
set(OPT_FLAGS "-O3 -flto")
set(MISC_FLAGS "-std=c11 -pthread -s")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${MISC_FLAGS} ${WARN_FLAGS} ${OPT_FLAGS}")

set(VERSION_FILE "${CMAKE_SOURCE_DIR}/VERSION")
file(READ "${VERSION_FILE}" VERSION)
string(REGEX REPLACE "[ \t\r\n]" "" VERSION "${VERSION}")
add_compile_definitions("TUNDRA__VERSION_STRING=\"${VERSION}\"")

add_executable(${EXECUTABLE} ${SOURCES})

include(GNUInstallDirs)
install(TARGETS "${EXECUTABLE}" DESTINATION "${CMAKE_INSTALL_SBINDIR}")
install(FILES "${CONFIG_FILE}" DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/tundra-nat64")
