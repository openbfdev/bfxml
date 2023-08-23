/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#include <bfxml.h>
#include <bfxml/xml.h>
#include <bfdev/fsm.h>
#include <bfdev/ctype.h>
#include <bfdev/array.h>
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

struct xml_conetext {
    const struct bfdev_alloc *alloc;
    struct bfdev_fsm fsm;
    struct bfdev_array tbuff;
    struct bfxml_node *node;
    const char *origin;
    const char *content;
};

struct xml_desc {
    const char *name;
    enum xml_type type;
};

struct xml_string {
    const char *value;
    size_t len;
};

static const char
xml_reserve[] = {
    "<>&'\""
};

static int
text_record(struct xml_conetext *ctx, const char *str, size_t len)
{
    char *buff;

    buff = bfdev_array_push(&ctx->tbuff, len);
    if (unlikely(!buff))
        return -BFDEV_ENOMEM;

    memcpy(buff, str, len);
    return -BFDEV_ENOERR;
}

static int
text_apply(struct xml_conetext *ctx, enum xml_type type)
{
    const struct bfdev_alloc *alloc;
    struct bfxml_node *node;
    size_t length;
    char *buff;

    alloc = ctx->alloc;
    node = ctx->node;
    length = bfdev_array_size(&ctx->tbuff);

    buff = bfdev_malloc(alloc, length + 1);
    if (unlikely(!buff))
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
text_verify(struct xml_conetext *ctx)
{
    struct bfxml_node *node;
    size_t length;
    int retval;

    node = ctx->node;
    length = bfdev_array_size(&ctx->tbuff);
    if (unlikely(!length))
        return false;

    retval = !strncmp(ctx->tbuff.data, node->name, length);
    bfdev_array_reset(&ctx->tbuff);

    return retval;
}

static int
child_enter(struct xml_conetext *ctx, enum xml_type type)
{
    const struct bfdev_alloc *alloc;
    struct bfxml_node *child, *parent;

    alloc = ctx->alloc;
    parent = ctx->node;

    child = bfdev_zalloc(alloc, sizeof(*child));
    if (unlikely(!child))
        return -BFDEV_ENOMEM;

    bfdev_list_head_init(&child->child);
    bfdev_list_add_prev(&parent->child, &child->sibling);
    child->parent = parent;
    ctx->node = child;

    switch (type) {
        case XML_TYPE_NAME:
            bfxml_set_object(child);
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
child_exit(struct xml_conetext *ctx)
{
    struct bfxml_node *parent;

    if (unlikely(!(parent = ctx->node->parent)))
        return BFDEV_FSM_FINISH;

    ctx->node = parent;
    return -BFDEV_ENOERR;
}

static long
guard_compare(struct bfdev_fsm_event *event, const void *cond)
{
    struct xml_conetext *ctx = event->pdata;
    char value;

    value = (char)(uintptr_t)cond;
    return *ctx->content - value;
}

static long
guard_string(struct bfdev_fsm_event *event, const void *cond)
{
    struct xml_conetext *ctx = event->pdata;
    size_t length;

    length = strlen(cond);
    if (strncmp(ctx->content, cond, length))
        return 1;

    ctx->content += length - 1;
    return 0;
}

static long
guard_ctype(struct bfdev_fsm_event *event, const void *cond)
{
    struct xml_conetext *ctx = event->pdata;
    unsigned short value;

    value = bfdev_ctype_table[(unsigned char)*ctx->content];
    return !(value & (unsigned short)(uintptr_t)cond);
}

static long
guard_check(struct bfdev_fsm_event *event, const void *cond)
{
    struct xml_conetext *ctx = event->pdata;
    unsigned short value;

    if (strchr(xml_reserve, *ctx->content))
        return 1;

    value = bfdev_ctype_table[(unsigned char)*ctx->content];
    return !(value & (unsigned short)(uintptr_t)cond);
}

static int
action_content(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct xml_conetext *ctx = event->pdata;
    return text_record(ctx, ctx->content, 1);
}

static int
action_string(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct xml_conetext *ctx = event->pdata;
    struct xml_string *str = data;
    return text_record(ctx, str->value, str->len);
}

static int
action_escape(struct bfdev_fsm_event *event, void *data, void *curr, void *next)
{
    struct xml_conetext *ctx = event->pdata;
    char value, *endptr;
    int base = 10;

    if (*++ctx->content == 'x') {
        ctx->content++;
        base = 16;
    }

    value = strtoul(ctx->content, &endptr, base);
    if (value < 0x20)
        return 0;

    ctx->content = endptr - 1;
    return text_record(ctx, &value, 1);
}

static int
state_entry(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;
    struct xml_desc *desc = data;
    return child_enter(ctx, desc->type);
}

static int
state_exit(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;
    return child_exit(ctx);
}

static int
state_record(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;
    struct xml_desc *desc = data;
    return text_apply(ctx, desc->type);
}

static int
state_record_exit(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;
    struct xml_desc *desc = data;
    int retval;

    retval = text_apply(ctx, desc->type);
    if (unlikely(retval))
        return retval;

    return child_exit(ctx);
}

static int
state_check_exit(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;

    if (unlikely(!text_verify(ctx))) {
        bfdev_fsm_error(&ctx->fsm, event);
        return -BFDEV_EINVAL;
    }

    return child_exit(ctx);
}

static int
error_entry(struct bfdev_fsm_event *event, void *data)
{
    struct xml_conetext *ctx = event->pdata;
    struct xml_desc *desc;
    unsigned int line, column;
    const char *walk;

    line = 1;
    column = 0;

    for (walk = ctx->origin; walk <= ctx->content; ++walk) {
        if (*walk != '\n') {
            column++;
            continue;
        }

        column = 0;
        line++;
    }

    desc = bfdev_fsm_prev(&ctx->fsm)->data;
    printf("error on line %u column %u: '%c' in state %s\n",
            line, column, *ctx->content, desc->name);

    return 0;
}

static const struct bfdev_fsm_state
trans_table[] = {
    [XML_STATE_LABEL] = {
        .tnum = 5,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_ENAME],
                .cond = (void *)(uintptr_t)'/',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_IGNORE],
                .cond = (void *)(uintptr_t)'?',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_IGNORE],
                .cond = "!--",
                .guard = guard_string,
            },
            {
                .next = &trans_table[XML_STATE_NAME],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "label",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_NAME] = {
        .tnum = 4,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = (void *)(uintptr_t)'>',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_SPACE | BFDEV_CTYPE_HDSPA),
                .guard = guard_check,
            },
            {
                .next = &trans_table[XML_STATE_NAME],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
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
        .tnum = 5,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = (void *)(uintptr_t)'>',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_EXIT],
                .cond = (void *)(uintptr_t)'/',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ANAME],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_SPACE | BFDEV_CTYPE_HDSPA),
                .guard = guard_check,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "await",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ANAME] = {
        .tnum = 3,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_EQUAL],
                .cond = (void *)(uintptr_t)'=',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ANAME],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "aname",
            .type = XML_TYPE_ANAME,
        },
        .enter = state_entry,
        .exit = state_record,
    },

    [XML_STATE_EQUAL] = {
        .tnum = 3,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_ASQUOTA],
                .cond = (void *)(uintptr_t)'\'',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ADQUOTA],
                .cond = (void *)(uintptr_t)'"',
                .guard = guard_compare,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "equal",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ASQUOTA] = {
        .tnum = 5,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .cond = (void *)(uintptr_t)'\'',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .cond = (void *)(uintptr_t)'&',
                .guard = guard_compare,
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_ASQUOTA],
                .cond = (void *)(uintptr_t)'"',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_ASQUOTA],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "asquota",
            .type = XML_TYPE_AVALUE,
        },
        .exit = state_record_exit,
    },

    [XML_STATE_ADQUOTA] = {
        .tnum = 5,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_AWAIT],
                .cond = (void *)(uintptr_t)'"',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .cond = (void *)(uintptr_t)'&',
                .guard = guard_compare,
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_ADQUOTA],
                .cond = (void *)(uintptr_t)'\'',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_ADQUOTA],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "adquota",
            .type = XML_TYPE_AVALUE,
        },
        .exit = state_record_exit,
    },

    [XML_STATE_BODY] = {
        .tnum = 6,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_LABEL],
                .cond = (void *)(uintptr_t)'<',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)'\'',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)'"',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_GRAPH),
                .guard = guard_check,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_SPACE | BFDEV_CTYPE_HDSPA),
                .guard = guard_check,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "body",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_STRING] = {
        .tnum = 6,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_LABEL],
                .cond = (void *)(uintptr_t)'<',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ESCAPE],
                .cond = (void *)(uintptr_t)'&',
                .guard = guard_compare,
                .stack = +1,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)'\'',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)'"',
                .guard = guard_compare,
                .action = action_content,
            },
            {
                .next = &trans_table[XML_STATE_STRING],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_SPACE | BFDEV_CTYPE_PRINT),
                .guard = guard_check,
                .action = action_content,
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
        .tnum = 2,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = (void *)(uintptr_t)'>',
                .guard = guard_compare,
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
        .tnum = 3,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = (void *)(uintptr_t)'>',
                .guard = guard_compare,
            },
            {
                .next = &trans_table[XML_STATE_ENAME],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_PRINT),
                .guard = guard_check,
                .action = action_content,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "ename",
            .type = XML_TYPE_NAME,
        },
        .exit = state_check_exit,
    },

    [XML_STATE_IGNORE] = {
        .tnum = 3,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_BODY],
                .cond = "-->",
                .guard = guard_string,
            },
            {
                .next = &trans_table[XML_STATE_IGNORE],
                .cond = (void *)(uintptr_t)(BFDEV_CTYPE_ASCII),
                .guard = guard_ctype,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "ignore",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_ESCAPE] = {
        .tnum = 7,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "amp",
                .guard = guard_string,
                .action = action_string,
                .data = &(struct xml_string) {
                    .value = "&",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "quot",
                .guard = guard_string,
                .action = action_string,
                .data = &(struct xml_string) {
                    .value = "\"",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "apos",
                .guard = guard_string,
                .action = action_string,
                .data = &(struct xml_string) {
                    .value = "'",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "lt",
                .guard = guard_string,
                .action = action_string,
                .data = &(struct xml_string) {
                    .value = "<",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = "gt",
                .guard = guard_string,
                .action = action_string,
                .data = &(struct xml_string) {
                    .value = ">",
                    .len = 1,
                },
            },
            {
                .next = &trans_table[XML_STATE_EEXIT],
                .cond = (void *)(uintptr_t)'#',
                .guard = guard_compare,
                .action = action_escape,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "escape",
            .type = XML_TYPE_DUMMY,
        },
    },

    [XML_STATE_EEXIT] = {
        .tnum = 2,
        .trans = (struct bfdev_fsm_transition []) {
            {
                .cond = (void *)(uintptr_t)';',
                .guard = guard_compare,
                .stack = -1,
            },
            { }, /* NULL */
        },
        .data = &(struct xml_desc) {
            .name = "eexit",
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
bfxml_decode(const struct bfdev_alloc *alloc, const char *buff,
             struct bfxml_node **rootp)
{
    struct xml_conetext ctx;
    struct bfxml_node *root;
    int retval;

    root = bfdev_zalloc(alloc, sizeof(*root));
    if (unlikely(!root))
        return -BFDEV_ENOMEM;

    root->flags = BFXML_IS_OBJECT;
    bfdev_list_head_init(&root->child);

    ctx.node = root;
    ctx.alloc = alloc;
    ctx.origin = buff;
    bfdev_array_init(&ctx.tbuff, alloc, sizeof(*buff));

    bfdev_fsm_init(
        &ctx.fsm, alloc,
        &trans_table[XML_STATE_BODY],
        &trans_table[XML_STATE_ERROR]
    );

    for (ctx.content = buff; *ctx.content; ++ctx.content) {
        retval = bfdev_fsm_handle(
            &ctx.fsm, &(struct bfdev_fsm_event) {
                .pdata = &ctx,
            }
        );
        if (retval == BFDEV_FSM_FINISH)
            break;

        if (retval < 0)
            return retval;
    }

    *rootp = root;
    return -BFDEV_ENOERR;
}
