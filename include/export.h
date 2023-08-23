/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2023 John Sanpe <sanpeqf@gmail.com>
 */

#ifndef _EXPORT_H_
#define _EXPORT_H_

#include <bfxml/config.h>

#undef hidden
# define hidden __bfdev_visibility("hidden")

#undef export
# define export __bfdev_visibility("default")

#endif /* _EXPORT_H_ */
