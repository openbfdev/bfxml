# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
#

add_executable(selftest selftest.c)
target_link_libraries(selftest bfxml_object)
add_test(selftest selftest COMMAND selftest.xml)

if(${CMAKE_PROJECT_NAME} STREQUAL "bfxml")
    install(FILES
        selftest.c
        DESTINATION
        ${CMAKE_INSTALL_DOCDIR}/examples
    )

    install(TARGETS
        selftest
        DESTINATION
        ${CMAKE_INSTALL_DOCDIR}/bin
    )
endif()
