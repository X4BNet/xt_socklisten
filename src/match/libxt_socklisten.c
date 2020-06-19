/*
 * Shared library add-on to iptables to add early socket matching support.
 *
 * Copyright (C) 2007 BalaBit IT Ltd.
 */
#include <stdio.h>
#include <xtables.h>
#include "xt_socklisten.h"

enum {
	O_TRANSPARENT = 0,
	O_NOWILDCARD = 1,
	O_RESTORESKMARK = 2,
};

static const struct xt_option_entry socklisten_mt_opts[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static const struct xt_option_entry socklisten_mt_opts_v2[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	{.name = "nowildcard", .id = O_NOWILDCARD, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static const struct xt_option_entry socklisten_mt_opts_v3[] = {
	{.name = "transparent", .id = O_TRANSPARENT, .type = XTTYPE_NONE},
	{.name = "nowildcard", .id = O_NOWILDCARD, .type = XTTYPE_NONE},
	{.name = "restore-skmark", .id = O_RESTORESKMARK, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static void socklisten_mt_help(void)
{
	printf(
		"socklisten match options:\n"
		"  --transparent    Ignore non-transparent sockets\n\n");
}

static void socklisten_mt_help_v2(void)
{
	printf(
		"socklisten match options:\n"
		"  --nowildcard     Do not ignore LISTEN sockets bound on INADDR_ANY\n"
		"  --transparent    Ignore non-transparent sockets\n\n");
}

static void socklisten_mt_help_v3(void)
{
	printf(
		"socklisten match options:\n"
		"  --nowildcard     Do not ignore LISTEN sockets bound on INADDR_ANY\n"
		"  --transparent    Ignore non-transparent sockets\n"
		"  --restore-skmark Set the packet mark to the socket mark if\n"
		"                   the socket matches and transparent / \n"
		"                   nowildcard conditions are satisfied\n\n");
}

static void socklisten_mt_parse(struct xt_option_call *cb)
{
	struct xt_socklisten_mtinfo1 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKLISTEN_TRANSPARENT;
		break;
	}
}

static void socklisten_mt_parse_v2(struct xt_option_call *cb)
{
	struct xt_socklisten_mtinfo2 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKLISTEN_TRANSPARENT;
		break;
	case O_NOWILDCARD:
		info->flags |= XT_SOCKLISTEN_NOWILDCARD;
		break;
	}
}

static void socklisten_mt_parse_v3(struct xt_option_call *cb)
{
	struct xt_socklisten_mtinfo2 *info = cb->data;

	xtables_option_parse(cb);
	switch (cb->entry->id) {
	case O_TRANSPARENT:
		info->flags |= XT_SOCKLISTEN_TRANSPARENT;
		break;
	case O_NOWILDCARD:
		info->flags |= XT_SOCKLISTEN_NOWILDCARD;
		break;
	case O_RESTORESKMARK:
		info->flags |= XT_SOCKLISTEN_RESTORESKMARK;
		break;
	}
}

static void
socklisten_mt_save(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socklisten_mtinfo1 *info = (const void *)match->data;

	if (info->flags & XT_SOCKLISTEN_TRANSPARENT)
		printf(" --transparent");
}

static void
socklisten_mt_print(const void *ip, const struct xt_entry_match *match,
		int numeric)
{
	printf(" socklisten");
	socklisten_mt_save(ip, match);
}

static void
socklisten_mt_save_v2(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socklisten_mtinfo2 *info = (const void *)match->data;

	if (info->flags & XT_SOCKLISTEN_TRANSPARENT)
		printf(" --transparent");
	if (info->flags & XT_SOCKLISTEN_NOWILDCARD)
		printf(" --nowildcard");
}

static void
socklisten_mt_print_v2(const void *ip, const struct xt_entry_match *match,
		   int numeric)
{
	printf(" socklisten");
	socklisten_mt_save_v2(ip, match);
}

static void
socklisten_mt_save_v3(const void *ip, const struct xt_entry_match *match)
{
	const struct xt_socklisten_mtinfo3 *info = (const void *)match->data;

	if (info->flags & XT_SOCKLISTEN_TRANSPARENT)
		printf(" --transparent");
	if (info->flags & XT_SOCKLISTEN_NOWILDCARD)
		printf(" --nowildcard");
	if (info->flags & XT_SOCKLISTEN_RESTORESKMARK)
		printf(" --restore-skmark");
}

static void
socklisten_mt_print_v3(const void *ip, const struct xt_entry_match *match,
		   int numeric)
{
	printf(" socklisten");
	socklisten_mt_save_v3(ip, match);
}

static struct xtables_match socklisten_mt_reg[] = {
	{
		.name          = "socklisten",
		.revision      = 0,
		.family        = NFPROTO_IPV4,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(0),
		.userspacesize = XT_ALIGN(0),
	},
	{
		.name          = "socklisten",
		.revision      = 1,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo1)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo1)),
		.help          = socklisten_mt_help,
		.print         = socklisten_mt_print,
		.save          = socklisten_mt_save,
		.x6_parse      = socklisten_mt_parse,
		.x6_options    = socklisten_mt_opts,
	},
	{
		.name          = "socklisten",
		.revision      = 2,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo2)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo2)),
		.help          = socklisten_mt_help_v2,
		.print         = socklisten_mt_print_v2,
		.save          = socklisten_mt_save_v2,
		.x6_parse      = socklisten_mt_parse_v2,
		.x6_options    = socklisten_mt_opts_v2,
	},
	{
		.name          = "socklisten",
		.revision      = 3,
		.family        = NFPROTO_UNSPEC,
		.version       = XTABLES_VERSION,
		.size          = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo2)),
		.userspacesize = XT_ALIGN(sizeof(struct xt_socklisten_mtinfo2)),
		.help          = socklisten_mt_help_v3,
		.print         = socklisten_mt_print_v3,
		.save          = socklisten_mt_save_v3,
		.x6_parse      = socklisten_mt_parse_v3,
		.x6_options    = socklisten_mt_opts_v3,
	},
};

void _init(void)
{
	xtables_register_matches(socklisten_mt_reg, 4);
}