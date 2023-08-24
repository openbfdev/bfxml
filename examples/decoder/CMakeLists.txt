# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
#

add_executable(decoder-selftest selftest.c)
target_link_libraries(decoder-selftest bfxml)
add_test(decoder-selftest decoder-selftest
    ${CMAKE_SOURCE_DIR}/testsuite/wap.xml
)

add_executable(decoder-benchmark benchmark.c)
target_link_libraries(decoder-benchmark bfxml)
add_test(decoder-benchmark decoder-benchmark
    ${CMAKE_SOURCE_DIR}/testsuite/wap.xml
)

if(${CMAKE_PROJECT_NAME} STREQUAL "bfxml")
    install(FILES
        selftest.c
        DESTINATION
        ${CMAKE_INSTALL_DOCDIR}/examples/decoder
    )

    install(TARGETS
        decoder-selftest
        decoder-benchmark
        DESTINATION
        ${CMAKE_INSTALL_DOCDIR}/bin
    )
endif()
