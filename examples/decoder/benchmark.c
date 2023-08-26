/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <bfxml/decoder.h>
#include "../helper.c"

#define TEST_LEN 100000

int main(int argc, char *argv[])
{
    struct bfxml_decoder *decoder;
    struct tms start_tms, stop_tms;
    clock_t start, stop;
    unsigned int count, ticks;
    struct stat stat;
    char *block;
    int retval;

    block = pathmap(&stat, argv[1]);
    printf("Decoder benchmark: %lu bytes * %u loops\n",
            stat.st_size, TEST_LEN);

    decoder = bfxml_decoder_create(NULL);
    if (!decoder) {
        printf("Failed to create decoder\n");
        return 1;
    }

    ticks = sysconf(_SC_CLK_TCK);
    start = times(&start_tms);
    for (count = 0; count < TEST_LEN; ++count) {
        retval = bfxml_decoder_handle(decoder, block, -1);
        if (retval) {
            show_error(decoder, block);
            return retval;
        }
    }
    stop = times(&stop_tms);
    time_dump(ticks, start, stop, &start_tms, &stop_tms);
    printf("\ttotal line: %u\n", count_line(block) * TEST_LEN);

    bfxml_release(NULL, decoder->root);
    bfxml_decoder_destory(decoder);
    munmap(block, stat.st_size);

    return retval;
}
