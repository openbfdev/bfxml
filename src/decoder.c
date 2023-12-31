/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <bfxml.h>
#include <bfxml/decoder.h>
#include <bfdev/ctype.h>
#include <export.h>

enum xml_state {
    XML_STATE_LABEL = 0,
    XML_STATE_NAME,
    XML_STATE_AWAIT,
    XML_STATE_ANAME,
    XML_STATE_EQUAL,
    XML_STATE_ASQUOTA,
    XML_STATE_ADQUOTA,
    XML_STATE_BODY,
    XML_STATE_STRING,
    XML_STATE_EXIT,
    XML_STATE_ENAME,
    XML_STATE_IGNORE,
    XML_STATE_IEXIT,
    XML_STATE_ESCAPE,
    XML_STATE_EEXIT,
    XML_STATE_ERROR,
};

enum xml_type {
    XML_TYPE_NAME = 0,
    XML_TYPE_ANAME,
    XML_TYPE_AVALUE,
    XML_TYPE_STRING,
    XML_TYPE_DUMMY,
};

struct xml_desc {
    const char *name;
    enum xml_type type;
};

struct xml_check {
    unsigned short type;
    const char *deny;
};

struct xml_string {
    const char *value;
    size_t len;
};

static int
text_record(struct bfxml_decoder *ctx, const char *str, size_t len)
{
    char *buff;

    buff = bfdev_array_push(&ctx->tbuff, len);
    if (bfdev_unlikely(!buff))
        return -BFDEV_ENOMEM;

    memcpy(buff, str, len);
    return -BFDEV_ENOERR;
}

static size_t
text_shrink(const char *buff, size_t length)
{
    size_t count;

    for (count = length; count; --count) {
        if (!isspace(buff[count - 1]))
            break;
    }

    return count;
}

static int
text_apply(struct bfxml_decoder *ctx, enum xml_type type)
{
    const struct bfdev_alloc *alloc;
    struct bfxml_node *node;
    size_t length;
    char *buff;

    alloc = ctx->alloc;
    node = ctx->node;

    length = bfdev_array_size(&ctx->tbuff);
    if (!length)
        return -BFDEV_ENOERR;

    if (type == XML_TYPE_STRING)
        length = text_shrink(ctx->tbuff.data, length);

    buff = bfdev_malloc(alloc, length + 1);
    if (bfdev_unlikely(!buff))
        return -BFDEV_ENOMEM;

    memcpy(buff, ctx->tbuff.data, length);
    bfdev_array_reset(&ctx->tbuff);
    buff[length] = '\0';

    switch (type) {
        case XML_TYPE_NAME:
            node->name = buff;
            break;

        case XML_TYPE_ANAME:
            node->attr_name = buff;
            break;

        case XML_TYPE_AVALUE:
            node->attr_value = buff;
            break;

        case XML_TYPE_STRING:
            node->string = buff;
            break;

        default:
            return -BFDEV_EINVAL;
    }

    return -BFDEV_ENOERR;
}

static bool
text_verify(struct bfxml_decoder *ctx)
{
    struct bfxml_node *node;
    size_t length;
    int retval;

    node = ctx->node;
    length = bfdev_array_size(&ctx->tbuff);
    if (bfdev_unlikely(!length))
        return false;

    retval = !strncmp(ctx->tbuff.data, node->name, length);
    bfdev_array_reset(&ctx->tbuff);

    return retval;
}

static int
child_enter(struct bfxml_decoder *ctx, enum xml_type type)
{
    const struct bfdev_alloc *alloc;
    struct bfxml_node *child, *parent;

    alloc = ctx->alloc;
    parent = ctx->node;

    child = bfdev_zalloc(alloc, sizeof(*child));
    if (bfdev_unlikely(!child))
        return -BFDEV_ENOMEM;

    bfdev_list_add_prev(&parent->child, &child->sibling);
    child->parent = parent;
    ctx->node = child;

    switch (type) {
        case XML_TYPE_NAME:
            bfxml_set_object(child);
            bfdev_list_head_init(&child->child);
            break;

        case XML_TYPE_ANAME: case XML_TYPE_AVALUE:
            bfxml_set_attribute(child);
            break;

        case XML_TYPE_STRING:
            bfxml_set_string(child);
            break;

        default:
            return -BFDEV_EINVAL;
    }

    return -BFDEV_ENOERR;
}

static int
child_exit(struct bfxml_decoder *ctx)
{
    struct bfxml_node *parent;

    if (bfdev_unlikely(!(parent = ctx->node->parent)))
        return BFDEV_FSM_FINISH;

    ctx->node->complete = true;
    ctx->node = parent;

    return -BFDEV_ENOERR;
}

static long
check_compare(struct bfdev_fsm_event *event, const void *cond)
{
    struct bfxml_decoder *ctx = event->pdata;
    char value;

    value = (char)(uintptr_t)cond;
    return *ctx->curr - value;
}

static long
check_string(struct bfdev_fsm_event *event, const void *cond)
{
    struct bfxml_decoder *ctx = event->pdata;
    size_t length;

    length = strlen(cond);
    if (strncmp(ctx->curr, cond, length))
        return 1;

    ctx->curr += length - 1;
    return 0;
}

static long
check_char(struct bfdev_fsm_event *event, const void *cond)
{
    struct bfxml_decoder *ctx = event->pdata;
    const struct xml_check *check = cond;
    unsigned char value;

    value = (unsigned char)*ctx->curr;
    if (!(bfdev_ctype_table[value] & check->type))
        return 1;

    return !!strchr(check->deny, *ctx->curr);
}

static int
record_curr(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct bfxml_decoder *ctx = event->pdata;
    return text_record(ctx, ctx->curr, 1);
}

static int
record_string(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct bfxml_decoder *ctx = event->pdata;
    struct xml_string *str = data;
    return text_record(ctx, str->value, str->len);
}

static int
record_escape(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct bfxml_decoder *ctx = event->pdata;
    char value, *endptr;
    int base = 10;

    if (*++ctx->curr == 'x') {
        ctx->curr++;
        base = 16;
    }

    value = strtoul(ctx->curr, &endptr, base);
    if (value < 0x20)
        return 0;

    ctx->curr = endptr - 1;
    return text_record(ctx, &value, 1);
}

static int
state_entry(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;
    struct xml_desc *desc = data;
    return child_enter(ctx, desc->type);
}

static int
state_exit(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;
    return child_exit(ctx);
}

static int
state_record(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;
    struct xml_desc *desc = data;
    return text_apply(ctx, desc->type);
}

static int
state_record_exit(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;
    struct xml_desc *desc = data;
    int retval;

    retval = text_apply(ctx, desc->type);
    if (bfdev_unlikely(retval))
        return retval;

    return child_exit(ctx);
}

static int
state_check_exit(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;

    if (bfdev_unlikely(!text_verify(ctx))) {
        bfdev_fsm_error(&ctx->fsm, event);
        return -BFDEV_EINVAL;
    }

    return child_exit(ctx);
}

static int
error_entry(struct bfdev_fsm_event *event, void *data)
{
    struct bfxml_decoder *ctx = event->pdata;
    struct xml_desc *desc;

    desc = bfdev_fsm_prev(&ctx->fsm)->data;
    printf("XML Parsing Error: %s\n", desc->name);

    return 0;
}

static const struct bfdev_fsm_state
trans_table[] = {
    [XML_STATE_LABEL] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_ENAME],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'/',
            },
            {
                .next = &trans_table[XML_STATE_IGNORE],
                .guard = check_string,
                .cond = "!--",
            },
            {
                .next = &trans_table[XML_STATE_NAME],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_GRAPH,
                    .deny = "<>&'\"",
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "label",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_NAME] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'>',
            },
            {
                .next = &trans_table[XML_STATE_NAME],
                .action = record_curr,
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'_',
            },
            {
                .next = &trans_table[XML_STATE_NAME],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_ALNUM,
                    .deny = "<>&'\"",
                },
            },
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_SPACE,
                    .deny = "<>&'\"",
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "name",
            .type = XML_TYPE_NAME,
        },
        .enter = state_entry,
        .exit = state_record,
    },

    [XML_STATE_AWAIT] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'>',
            },
            {
                .next = &trans_table[XML_STATE_EXIT],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'/',
            },
            {
                .next = &trans_table[XML_STATE_ANAME],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_GRAPH,
                    .deny = "<>&'\"",
                },
            },
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_SPACE,
                    .deny = "<>&'\"",
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "attribute wait",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ANAME] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_EQUAL],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'=',
            },
            {
                .next = &trans_table[XML_STATE_ANAME],
                .action = record_curr,
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'_',
            },
            {
                .next = &trans_table[XML_STATE_ANAME],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_ALNUM,
                    .deny = "<>&'\"",
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "attribute name",
            .type = XML_TYPE_ANAME,
        },
        .enter = state_entry,
        .exit = state_record,
    },

    [XML_STATE_EQUAL] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_ASQUOTA],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'\'',
            },
            {
                .next = &trans_table[XML_STATE_ADQUOTA],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'"',
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "attribute equal",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ASQUOTA] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'\'',
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'&',
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_ASQUOTA],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_GRAPH,
                    .deny = "<>&'", /* allow ["] */
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "attribute single quota",
            .type = XML_TYPE_AVALUE,
        },
        .exit = state_record_exit,
    },

    [XML_STATE_ADQUOTA] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'"',
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'&',
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_ADQUOTA],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_SPACE | BFDEV_CTYPE_GRAPH,
                    .deny = "<>&\"", /* allow ['] */
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "attribute double quota",
            .type = XML_TYPE_AVALUE,
        },
        .exit = state_record_exit,
    },

    [XML_STATE_BODY] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_LABEL],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'<',
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'&',
                .cross = true,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_GRAPH,
                    .deny = "<>&", /* allow ['"] */
                },
            },
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_SPACE,
                    .deny = "<>&"
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "body",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_STRING] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_LABEL],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'<',
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'&',
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_SPACE | BFDEV_CTYPE_PRINT,
                    .deny = "<>&", /* allow ['"] */
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "string",
            .type = XML_TYPE_STRING,
        },
        .enter = state_entry,
        .exit = state_record_exit,
    },

    [XML_STATE_EXIT] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'>',
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "exit",
            .type = XML_TYPE_NAME,
        },
        .exit = state_exit,
    },

    [XML_STATE_ENAME] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'>',
            },
            {
                .next = &trans_table[XML_STATE_ENAME],
                .action = record_curr,
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_PRINT,
                    .deny = "<>&'\"",
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "exit name",
            .type = XML_TYPE_NAME,
        },
        .exit = state_check_exit,
    },

    [XML_STATE_IGNORE] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_IEXIT],
                .guard = check_string,
                .cond = "--",
            },
            {
                .next = &trans_table[XML_STATE_IGNORE],
                .guard = check_char,
                .cond = &(struct xml_check) {
                    .type = BFDEV_CTYPE_ASCII,
                    .deny = "", /* allow [<>&'"] */
                },
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "ignore",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_IEXIT] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'>',
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "ignore exit",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ESCAPE] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "amp",
                .action = record_string,
                .guard = check_string,
                .data = &(struct xml_string) {
                    .value = "&",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "quot",
                .action = record_string,
                .guard = check_string,
                .data = &(struct xml_string) {
                    .value = "\"",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "apos",
                .action = record_string,
                .guard = check_string,
                .data = &(struct xml_string) {
                    .value = "'",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "lt",
                .action = record_string,
                .guard = check_string,
                .data = &(struct xml_string) {
                    .value = "<",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "gt",
                .action = record_string,
                .guard = check_string,
                .data = &(struct xml_string) {
                    .value = ">",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .action = record_escape,
                .guard = check_compare,
                .cond = (void *)(uintptr_t)'#',
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "escape",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_EEXIT] = {
        .tnum = -1,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .guard = check_compare,
                .cond = (void *)(uintptr_t)';',
                .stack = -1,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "escape exit",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ERROR] = {
        .data = &(struct xml_desc) {
            .name = "error",
            .type = XML_TYPE_DUMMY,
        },
        .enter = error_entry,
    },
};

export int
bfxml_decoder_handle(struct bfxml_decoder *decoder, const char *data, size_t len)
{
    int retval;

    for (decoder->curr = data; *decoder->curr && len; --len) {
        retval = bfdev_fsm_handle(
            &decoder->fsm, &(struct bfdev_fsm_event) {
                .pdata = decoder,
            }
        );

        if (retval == BFDEV_FSM_FINISH)
            return -BFDEV_EFAULT;

        if (retval < 0)
            return retval;

        decoder->curr++;
    }

    return -BFDEV_ENOERR;
}

export struct bfxml_decoder *
bfxml_decoder_create(const struct bfdev_alloc *alloc)
{
    struct bfxml_decoder *decoder;
    struct bfxml_node *root;

    decoder = bfdev_zalloc(alloc, sizeof(*decoder));
    if (bfdev_unlikely(!decoder))
        return NULL;

    root = bfdev_zalloc(alloc, sizeof(*root));
    if (bfdev_unlikely(!root))
        return NULL;

    root->flags = BFXML_IS_OBJECT;
    bfdev_list_head_init(&root->child);

    decoder->alloc = alloc;
    decoder->root = root;
    decoder->node = root;
    bfdev_array_init(&decoder->tbuff, alloc, sizeof(*decoder->curr));

    bfdev_fsm_init(
        &decoder->fsm, alloc,
        &trans_table[XML_STATE_BODY],
        &trans_table[XML_STATE_ERROR]
    );

    return decoder;
}

export void
bfxml_decoder_destory(struct bfxml_decoder *decoder)
{
    const struct bfdev_alloc *alloc = decoder->alloc;
    bfdev_array_release(&decoder->tbuff);
    bfdev_free(alloc, decoder);
}
