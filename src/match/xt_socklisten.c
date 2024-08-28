// SPDX-License-Identifier: GPL-2.0-only
/*
 * Transparent proxy support for Linux/iptables
 *
 * Copyright (C) 2007-2008 BalaBit IT Ltd.
 * Author: Krisztian Kovacs
 */
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/netfilter/ipv4/nf_defrag_ipv4.h>

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <net/inet6_hashtables.h>
#include <net/netfilter/ipv6/nf_defrag_ipv6.h>
#endif

#include "xt_socklisten.h"

#include <net/netfilter/nf_socket.h>
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#endif

struct sock *nf_sk_lookup_v4(struct net *net, const struct sk_buff *skb,
				  const struct net_device *indev)
{
	__be32 daddr, saddr;
	__be16 dport, sport;
	const struct iphdr *iph = ip_hdr(skb);
	struct sk_buff *data_skb = NULL;
	u8 protocol;
#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	enum ip_conntrack_info ctinfo;
	struct nf_conn const *ct;
#endif
	int doff = 0;
	struct tcphdr _hdr; // fits a UDP header too
	struct tcphdr *hp;
	bool isTcp;
	struct sock* ret = NULL;

	protocol = iph->protocol;
	if (protocol != IPPROTO_UDP && protocol != IPPROTO_TCP) {
		return NULL;
	}

	isTcp = protocol == IPPROTO_TCP;
	doff = ip_hdrlen(skb);
	hp = skb_header_pointer(skb, doff,
				isTcp ?
				sizeof(_hdr): sizeof(struct udphdr), &_hdr);

	if (unlikely(hp == NULL))
		return NULL;

	saddr = iph->saddr;
	daddr = iph->daddr;
	sport = hp->source;
	dport = hp->dest;

	if(isTcp) {
		// don't lookup listeners for SYN-ACK packets
		if (hp->syn && hp->ack)
			return NULL;
	}

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
	/* Do the lookup with the original socket address in
	 * case this is a reply packet of an established
	 * SNAT-ted connection.
	 */
	ct = nf_ct_get(skb, &ctinfo);
	if (unlikely(ct && ctinfo == IP_CT_ESTABLISHED_REPLY)) {

		daddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
		dport = isTcp ?
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.tcp.port :
			ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.udp.port;
	}
#endif

	data_skb = (struct sk_buff *)skb;
	doff += (isTcp ? __tcp_hdrlen(hp) : sizeof(struct udphdr));


	if(isTcp) {
		ret = inet_lookup_listener(net, &tcp_hashinfo, skb, doff,
				   saddr, sport, daddr, dport,
				   ntohs(dport), indev->ifindex);
		if(ret && !refcount_inc_not_zero(&ret->sk_refcnt)){
			ret = NULL;
		}
	} else {
		ret = udp4_lib_lookup(net, saddr, sport, daddr, dport,
				       indev->ifindex);
	}

	return ret;
}

/* "socket" match based redirection (no specific rule)
 * ===================================================
 *
 * There are connections with dynamic endpoints (e.g. FTP data
 * connection) that the user is unable to add explicit rules
 * for. These are taken care of by a generic "socket" rule. It is
 * assumed that the proxy application is trusted to open such
 * connections without explicit iptables rule (except of course the
 * generic 'socket' rule). In this case the following sockets are
 * matched in preference order:
 *
 *   - match: if there's a fully established connection matching the
 *     _packet_ tuple
 *
 *   - match: if there's a non-zero bound listener (possibly with a
 *     non-local address) We don't accept zero-bound listeners, since
 *     then local services could intercept traffic going through the
 *     box.
 */
static bool socklisten_match(struct sk_buff *skb, struct xt_action_param *par)
{
	struct sock *sk = skb->sk;
	struct xt_socklisten_mtinfo1 *info;
	bool to_clear;

	if (!sk || !net_eq(xt_net(par), sock_net(sk)))
		sk = nf_sk_lookup_v4(xt_net(par), skb, xt_in(par));

	if (sk) {
		/* Ignore sockets listening on INADDR_ANY,
		 * unless XT_SOCKLISTEN_WILDCARD is set
		 */
		info = par->matchinfo;
		to_clear = (!(info->flags & XT_SOCKLISTEN_WILDCARD) &&
			    sk_fullsock(sk) &&
			    inet_sk(sk)->inet_rcv_saddr == 0);

		/* Ignore non-transparent sockets,
		 * if XT_SOCKLISTEN_TRANSPARENT is used
		 */
		if(!to_clear)
			to_clear = (info->flags & XT_SOCKLISTEN_TRANSPARENT) && !inet_sk_transparent(sk);
		
		if (info->flags & XT_SOCKLISTEN_RESTORESKMARK && !to_clear && sk_fullsock(sk))
			skb->mark = sk->sk_mark;

		if (sk != skb->sk)
			sock_gen_put(sk);

		if (to_clear)
			sk = NULL;
	}

	return sk != NULL;
}

static bool socklisten_mt4_v1_v2_v3(const struct sk_buff *skb, struct xt_action_param *par)
{
	return socklisten_match((struct sk_buff *)skb, par);
}

#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
static bool
socklisten_mt6_v1_v2_v3(const struct sk_buff *skb, struct xt_action_param *par)
{
	const struct xt_socklisten_mtinfo1 *info = (struct xt_socklisten_mtinfo1 *) par->matchinfo;
	struct sk_buff *pskb = (struct sk_buff *)skb;
	struct sock *sk = skb->sk;

	if (sk && !net_eq(xt_net(par), sock_net(sk)))
		sk = NULL;

	if (!sk)
		sk = nf_sk_lookup_slow_v6(xt_net(par), skb, xt_in(par));

	if (sk) {
		bool wildcard;
		bool transparent = true;

		/* Ignore sockets listening on INADDR_ANY
		 * unless XT_SOCKLISTEN_WILDCARD is set
		 */
		wildcard = (!(info->flags & XT_SOCKLISTEN_WILDCARD) &&
			    sk_fullsock(sk) &&
			    ipv6_addr_any(&sk->sk_v6_rcv_saddr));

		/* Ignore non-transparent sockets,
		 * if XT_SOCKLISTEN_TRANSPARENT is used
		 */
		if (info->flags & XT_SOCKLISTEN_TRANSPARENT)
			transparent = inet_sk_transparent(sk);

		if (info->flags & XT_SOCKLISTEN_RESTORESKMARK && !wildcard &&
		    transparent && sk_fullsock(sk))
			pskb->mark = sk->sk_mark;

		if (sk != skb->sk)
			sock_gen_put(sk);

		if (wildcard || !transparent)
			sk = NULL;
	}

	return sk != NULL;
}
#endif

static int socklisten_mt_enable_defrag(struct net *net, int family)
{
	switch (family) {
	case NFPROTO_IPV4:
		return nf_defrag_ipv4_enable(net);
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	case NFPROTO_IPV6:
		return nf_defrag_ipv6_enable(net);
#endif
	}
	WARN_ONCE(1, "Unknown family %d\n", family);
	return 0;
}

static int socklisten_mt_v1_check(const struct xt_mtchk_param *par)
{
	const struct xt_socklisten_mtinfo1 *info = (struct xt_socklisten_mtinfo1 *) par->matchinfo;
	int err;

	err = socklisten_mt_enable_defrag(par->net, par->family);
	if (err)
		return err;

	if (info->flags & ~XT_SOCKLISTEN_FLAGS_V1) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_SOCKLISTEN_FLAGS_V1);
		return -EINVAL;
	}
	return 0;
}

static int socklisten_mt_v2_check(const struct xt_mtchk_param *par)
{
	const struct xt_socklisten_mtinfo2 *info = (struct xt_socklisten_mtinfo2 *) par->matchinfo;
	int err;

	err = socklisten_mt_enable_defrag(par->net, par->family);
	if (err)
		return err;

	if (info->flags & ~XT_SOCKLISTEN_FLAGS_V2) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_SOCKLISTEN_FLAGS_V2);
		return -EINVAL;
	}
	return 0;
}

static int socklisten_mt_v3_check(const struct xt_mtchk_param *par)
{
	const struct xt_socklisten_mtinfo3 *info =
				    (struct xt_socklisten_mtinfo3 *)par->matchinfo;
	int err;

	err = socklisten_mt_enable_defrag(par->net, par->family);
	if (err)
		return err;
	if (info->flags & ~XT_SOCKLISTEN_FLAGS_V3) {
		pr_info_ratelimited("unknown flags 0x%x\n",
				    info->flags & ~XT_SOCKLISTEN_FLAGS_V3);
		return -EINVAL;
	}
	return 0;
}

static struct xt_match socklisten_mt_reg[] __read_mostly = {
	{
		.name		= "socklisten",
		.revision	= 1,
		.family		= NFPROTO_IPV4,
		.match		= socklisten_mt4_v1_v2_v3,
		.checkentry	= socklisten_mt_v1_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socklisten",
		.revision	= 1,
		.family		= NFPROTO_IPV6,
		.match		= socklisten_mt6_v1_v2_v3,
		.checkentry	= socklisten_mt_v1_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#endif
	{
		.name		= "socklisten",
		.revision	= 2,
		.family		= NFPROTO_IPV4,
		.match		= socklisten_mt4_v1_v2_v3,
		.checkentry	= socklisten_mt_v2_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socklisten",
		.revision	= 2,
		.family		= NFPROTO_IPV6,
		.match		= socklisten_mt6_v1_v2_v3,
		.checkentry	= socklisten_mt_v2_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#endif
	{
		.name		= "socklisten",
		.revision	= 3,
		.family		= NFPROTO_IPV4,
		.match		= socklisten_mt4_v1_v2_v3,
		.checkentry	= socklisten_mt_v3_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name		= "socklisten",
		.revision	= 3,
		.family		= NFPROTO_IPV6,
		.match		= socklisten_mt6_v1_v2_v3,
		.checkentry	= socklisten_mt_v3_check,
		.matchsize	= sizeof(struct xt_socklisten_mtinfo1),
		.hooks		= (1 << NF_INET_PRE_ROUTING) |
				  (1 << NF_INET_LOCAL_IN),
		.me		= THIS_MODULE,
	},
#endif
};

static int __init socklisten_mt_init(void)
{
	return xt_register_matches(socklisten_mt_reg, ARRAY_SIZE(socklisten_mt_reg));
}

static void __exit socklisten_mt_exit(void)
{
	xt_unregister_matches(socklisten_mt_reg, ARRAY_SIZE(socklisten_mt_reg));
}

module_init(socklisten_mt_init);
module_exit(socklisten_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mathew Heard");
MODULE_DESCRIPTION("x_tables listening socket match module");
MODULE_ALIAS("ipt_socklisten");
MODULE_ALIAS("ip6t_socketlisten");