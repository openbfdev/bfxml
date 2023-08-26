# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
#

cmake_minimum_required(VERSION 3.9)
project(bfxml VERSION "1.0" LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFiles)

add_definitions(
    " -std=gnu17"
    " -Wall"
    " -Wextra"
    " -Werror"
    " -Wno-unused-parameter"
)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(BFXML_HEADER_PATH ${PROJECT_SOURCE_DIR}/include)
set(BFXML_GENERATED_PATH ${PROJECT_BINARY_DIR}/generated)
option(ENABLE_EXAMPLES "Build examples" OFF)

configure_file(
    ${CMAKE_MODULE_PATH}/config.h.in
    ${PROJECT_BINARY_DIR}/generated/bfxml/config.h
)

FILE(GLOB_RECURSE SRC_HEADER "include/*.h")
FILE(GLOB_RECURSE SRC_SOURCE "src/*.c")
include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_BINARY_DIR}/generated)

set(BFXML_LIBRARY
    ${SRC_HEADER}
    ${SRC_SOURCE}
)

add_library(bfxml_object OBJECT ${BFXML_LIBRARY})
add_library(bfxml_static STATIC ${BFXML_LIBRARY})
add_library(bfxml_shared SHARED ${BFXML_LIBRARY})
add_library(bfxml ALIAS bfxml_object)

set_target_properties(bfxml_static
    PROPERTIES
    OUTPUT_NAME bfxml
    LINKER_LANGUAGE C
)

set_target_properties(bfxml_shared
    PROPERTIES VERSION 1.0 SOVERSION 1
    OUTPUT_NAME bfxml
    MACOSX_RPATH ON
    LINKER_LANGUAGE C
)

target_link_libraries(bfxml_object bfdev)
target_link_libraries(bfxml_static bfdev)
target_link_libraries(bfxml_shared bfdev)

if(ENABLE_EXAMPLES)
    enable_testing()
    add_subdirectory(examples)
endif()

if(${CMAKE_PROJECT_NAME} STREQUAL "bfxml")
    install(DIRECTORY
        ${BFXML_HEADER_PATH}/bfxml
        ${BFXML_GENERATED_PATH}/bfxml
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    install(TARGETS
        bfxml_static bfxml_shared
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
endif()
