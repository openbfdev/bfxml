/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#ifndef _BFXML_CORE_H_
#define _BFXML_CORE_H_

#include <bfxml/config.h>
#include <bfdev/errno.h>
#include <bfdev/list.h>
#include <bfdev/bitflags.h>
#include <bfdev/allocator.h>

BFDEV_BEGIN_DECLS

enum bfxml_flags {
    __BFXML_IS_OBJECT = 0,
    __BFXML_IS_ATTRIBUTE,
    __BFXML_IS_STRING,

    BFXML_IS_OBJECT     = BFDEV_BIT(__BFXML_IS_OBJECT),
    BFXML_IS_ATTRIBUTE  = BFDEV_BIT(__BFXML_IS_ATTRIBUTE),
    BFXML_IS_STRING     = BFDEV_BIT(__BFXML_IS_STRING),
};

struct bfxml_node {
    struct bfxml_node *parent;
    struct bfdev_list_head sibling;
    unsigned long flags;
    bool complete;

    union {
        /* object */
        struct {
            char *name;
            struct bfdev_list_head child;
        };

        /* attribute */
        struct {
            char *attr_name;
            char *attr_value;
        };

        /* string */
        char *string;
    };
};

BFDEV_BITFLAGS_STRUCT(bfxml, struct bfxml_node, flags)
BFDEV_BITFLAGS_STRUCT_FLAG(bfxml, struct bfxml_node, flags, object, __BFXML_IS_OBJECT)
BFDEV_BITFLAGS_STRUCT_FLAG(bfxml, struct bfxml_node, flags, attribute, __BFXML_IS_ATTRIBUTE)
BFDEV_BITFLAGS_STRUCT_FLAG(bfxml, struct bfxml_node, flags, string, __BFXML_IS_STRING)

extern int bfxml_encode(struct bfxml_node *root, char *buff, int size);
extern void bfxml_release(const struct bfdev_alloc *alloc, struct bfxml_node *root);

BFDEV_END_DECLS

#endif /* _BFXML_CORE_H_ */
