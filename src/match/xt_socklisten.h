/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _XT_SOCKLISTEN_H
#define _XT_SOCKLISTEN_H

#include <linux/types.h>

enum {
	XT_SOCKLISTEN_TRANSPARENT = 1 << 0,
	XT_SOCKLISTEN_WILDCARD = 1 << 1,
	XT_SOCKLISTEN_RESTORESKMARK = 1 << 2,
};

struct xt_socklisten_mtinfo1 {
	__u8 flags;
};
#define XT_SOCKLISTEN_FLAGS_V1 XT_SOCKLISTEN_TRANSPARENT

struct xt_socklisten_mtinfo2 {
	__u8 flags;
};
#define XT_SOCKLISTEN_FLAGS_V2 (XT_SOCKLISTEN_TRANSPARENT | XT_SOCKLISTEN_WILDCARD)

struct xt_socklisten_mtinfo3 {
	__u8 flags;
};
#define XT_SOCKLISTEN_FLAGS_V3 (XT_SOCKLISTEN_TRANSPARENT \
			   | XT_SOCKLISTEN_WILDCARD \
			   | XT_SOCKLISTEN_RESTORESKMARK)

#endif /* _XT_SOCKLISTEN_H */