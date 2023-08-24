/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <bfxml/decoder.h>
#include "../helper.c"

static void
dump_info(struct bfxml_node *parent, unsigned int depth)
{
    struct bfxml_node *child;
    unsigned int count;

    printf("object: %s {\n", parent->name);
    bfdev_list_for_each_entry(child, &parent->child, sibling) {
        for (count = 0; count < depth; ++count)
            printf("\t");
        if (bfxml_test_object(child)) {
            dump_info(child, depth + 1);
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

static void
show_error(struct bfxml_decoder *decoder, char *block)
{
    unsigned int count;
    char *end;

    for (count = 1; count < decoder->line; ++count) {
        block = strchr(block, '\n');
        if (!block++)
            return;
    }

    end = strchr(block, '\n');
    count = end ? end - block : -1;
    printf("%.*s\n", count, block);

    for (count = 1; count < decoder->column; ++count)
        printf("-");
    printf("^\n");
}

int main(int argc, char *argv[])
{
    struct bfxml_decoder *decoder;
    struct bfxml_node *xnode;
    struct stat stat;
    char *block;
    int retval;

    block = pathmap(&stat, argv[1]);
    decoder = bfxml_decoder_create(NULL);
    if (!decoder) {
        printf("failed to create decoder\n");
        return 1;
    }

    retval = bfxml_decoder_handle(decoder, block, -1);
    if (retval) {
        show_error(decoder, block);
        return retval;
    }

    xnode = decoder->root;
    bfxml_decoder_destory(decoder);

    printf("pseudo expression:\n");
    dump_info(xnode, 1);

    bfxml_release(NULL, xnode);
    munmap(block, stat.st_size);

    return retval;
}
