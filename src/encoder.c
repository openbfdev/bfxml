/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <bfxml.h>
#include <bfxml/core.h>
#include <bfdev/minmax.h>
#include <export.h>

static int
encode_depth(struct bfxml_node *parent, char *buff, int size, int len, unsigned int depth)
{
    #define xml_sprintf(fmt, ...) len += snprintf(buff + len, bfdev_max(0, size - len), fmt, ##__VA_ARGS__)
    struct bfxml_node *child, *attr;
    unsigned int count;
    int save;

    bfdev_list_for_each_entry(child, &parent->child, sibling) {
        if (bfxml_test_attribute(child))
            continue;

        for (count = 0; count < depth; ++count)
            xml_sprintf("\t");

        if (bfxml_test_string(child))
            xml_sprintf("%s\n", child->attr_name);
        else if (bfxml_test_object(child)) {
            xml_sprintf("<%s", child->name);
            bfdev_list_for_each_entry(attr, &child->child, sibling) {
                if (bfxml_test_attribute(attr))
                    xml_sprintf(" %s=\"%s\"", attr->attr_name, attr->attr_value);
            }
            xml_sprintf(">\n");

            save = len;
            len = encode_depth(child, buff, size, len, depth + 1);

            if (len == save) {
                len -= 2;
                xml_sprintf("/>\n");
            } else {
                for (count = 0; count < depth; ++count)
                    xml_sprintf("\t");
                xml_sprintf("</%s>\n", child->name);
            }
        }
    }

    return len;
}

export int
bfxml_encode(struct bfxml_node *root, char *buff, int size)
{
    return encode_depth(root, buff, size, 0, 0) + 1;
}
