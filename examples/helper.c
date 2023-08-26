/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/times.h>
#include <sys/stat.h>

static inline void *
pathmap(struct stat *stat, const char *path)
{
    void *block;
    int fd;

    if ((fd = open(path, O_RDONLY)) < 0)
        err(errno, path);

    if ((errno = fstat(fd, stat)) < 0)
        err(errno, path);

    block = mmap(NULL, stat->st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (block == MAP_FAILED)
        err(errno, path);

    return block;
}

static inline void
time_dump(int ticks, clock_t start, clock_t stop, struct tms *start_tms, struct tms *stop_tms)
{
    printf("\treal time: %lf\n", (stop - start) / (double)ticks);
    printf("\tuser time: %lf\n", (stop_tms->tms_utime - start_tms->tms_utime) / (double)ticks);
    printf("\tkern time: %lf\n", (stop_tms->tms_stime - start_tms->tms_stime) / (double)ticks);
}

static inline unsigned int
count_line(const char *start)
{
    unsigned int line = 1;

    while ((start = strchr(start, '\n'))) {
        start++;
        line++;
    }

    return line;
}

static inline void
show_error(struct bfxml_decoder *decoder, const char *start)
{
    unsigned int line, column, count;
    const char *walk;
    int size;

    column = 1;
    line = 1;

    for (walk = start; walk <= decoder->curr; ++walk) {
        if (*walk != '\n') {
            column++;
            continue;
        }

        start = walk;
        column = 0;
        line++;
    }

    walk = strchr(walk, '\n');
    size = walk ? walk - ++start: -1;

    printf("Line Number %u, Column %u\n", line, column);
    printf("%.*s\n", size, start);

    for (count = 1; count < column; ++count)
        printf("-");
    printf("^\n");
}
