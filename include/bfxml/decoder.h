/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#ifndef _BFXML_DECODE_H_
#define _BFXML_DECODE_H_

#include <bfxml/config.h>
#include <bfxml/core.h>
#include <bfdev/fsm.h>
#include <bfdev/array.h>

BFDEV_BEGIN_DECLS

struct bfxml_decoder {
    const struct bfdev_alloc *alloc;
    struct bfdev_fsm fsm;
    struct bfdev_array tbuff;

    unsigned int column;
    unsigned int line;

    struct bfxml_node *root;
    struct bfxml_node *node;
    const char *curr;
};

extern int
bfxml_decoder_handle(struct bfxml_decoder *decoder, const char *data, size_t len);

extern struct bfxml_decoder *
bfxml_decoder_create(const struct bfdev_alloc *alloc);

extern void
bfxml_decoder_destory(struct bfxml_decoder *decoder);

BFDEV_END_DECLS

#endif /* _BFXML_DECODE_H_ */
