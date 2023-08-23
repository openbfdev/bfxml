/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2022 Sanpe <sanpeqf@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <bfxml/xml.h>

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

static void
xml_dumpinfo(struct bfxml_node *parent, unsigned int depth)
{
    struct bfxml_node *child;
    unsigned int count;

    printf("object: %s {\n", parent->name);
    bfdev_list_for_each_entry(child, &parent->child, sibling) {
        for (count = 0; count < depth; ++count)
            printf("\t");
        if (bfxml_test_object(child)) {
            xml_dumpinfo(child, depth + 1);
            continue;
        }
        if (bfxml_test_attribute(child))
            printf("attribute: %s=%s", child->attr_name, child->attr_value);
        else if (bfxml_test_string(child))
            printf("string: %s", child->attr_name);
        printf("\n");
    }

    for (count = 0; count < depth - 1; ++count)
        printf("\t");
    printf("}\n");
}

int main(int argc, char *argv[])
{
    struct bfxml_node *xnode;
    struct stat stat;
    int length, retval;
    char *buff, *block;

    block = pathmap(&stat, argv[1]);
    retval = bfxml_decode(NULL, block, &xnode);
    if (retval)
        return retval;

    printf("pseudo expression:\n");
    xml_dumpinfo(xnode, 1);

    printf("xml encode:\n");
    length = bfxml_encode(xnode, NULL, 0);

    buff = malloc(length);
    if (!buff) {
        retval = 1;
        goto finish;
    }

    length = bfxml_encode(xnode, buff, length);
    fwrite(buff, length, 1, stdout);
    free(buff);

finish:
    bfxml_release(NULL, xnode);
    munmap(block, stat.st_size);
    return retval;
}
