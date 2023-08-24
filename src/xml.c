/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <bfxml.h>
#include <bfxml/core.h>
#include <export.h>

export void
bfxml_release(const struct bfdev_alloc *alloc, struct bfxml_node *root)
{
    struct bfxml_node *node, *tmp;

    if (unlikely(!root))
        return;

    bfdev_list_for_each_entry_safe(node, tmp, &root->child, sibling) {
        bfdev_list_del(&node->sibling);
        if (bfxml_test_object(node)) {
            bfxml_release(alloc, node);
            continue;
        }

        if (bfxml_test_string(node))
            bfdev_free(alloc, node->string);
        else if (bfxml_test_attribute(node)) {
            bfdev_free(alloc, node->attr_name);
            bfdev_free(alloc, node->attr_value);
        }

        bfdev_free(alloc, node);
    };

    bfdev_free(alloc, root->name);
    bfdev_free(alloc, root);
}
