// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/rhashtable.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <net/gso.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack_acct.h>
/* For layer 4 checksum field offset. */
#include <linux/tcp.h>
#include <linux/udp.h>

static int nf_flow_state_check(struct flow_offload *flow, int proto,
			       struct sk_buff *skb, unsigned int thoff)
{
	struct tcphdr *tcph;

	if (proto != IPPROTO_TCP)
		return 0;

	tcph = (void *)(skb_network_header(skb) + thoff);
	if (unlikely(tcph->fin || tcph->rst)) {
		flow_offload_teardown(flow);
		return -1;
	}

	return 0;
}

static void nf_flow_nat_ip_tcp(struct sk_buff *skb, unsigned int thoff,
			       __be32 addr, __be32 new_addr)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, true);
}

static void nf_flow_nat_ip_udp(struct sk_buff *skb, unsigned int thoff,
			       __be32 addr, __be32 new_addr)
{
	struct udphdr *udph;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace4(&udph->check, skb, addr,
					 new_addr, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
}

static void nf_flow_nat_ip_l4proto(struct sk_buff *skb, struct iphdr *iph,
				   unsigned int thoff, __be32 addr,
				   __be32 new_addr)
{
	switch (iph->protocol) {
	case IPPROTO_TCP:
		nf_flow_nat_ip_tcp(skb, thoff, addr, new_addr);
		break;
	case IPPROTO_UDP:
		nf_flow_nat_ip_udp(skb, thoff, addr, new_addr);
		break;
	}
}

static void nf_flow_snat_ip(const struct flow_offload *flow,
			    struct sk_buff *skb, struct iphdr *iph,
			    unsigned int thoff, enum flow_offload_tuple_dir dir)
{
	__be32 addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v4.s_addr;
		iph->saddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v4.s_addr;
		iph->daddr = new_addr;
		break;
	}
	csum_replace4(&iph->check, addr, new_addr);

	nf_flow_nat_ip_l4proto(skb, iph, thoff, addr, new_addr);
}

static void nf_flow_dnat_ip(const struct flow_offload *flow,
			    struct sk_buff *skb, struct iphdr *iph,
			    unsigned int thoff, enum flow_offload_tuple_dir dir)
{
	__be32 addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = iph->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v4.s_addr;
		iph->daddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = iph->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v4.s_addr;
		iph->saddr = new_addr;
		break;
	}
	csum_replace4(&iph->check, addr, new_addr);

	nf_flow_nat_ip_l4proto(skb, iph, thoff, addr, new_addr);
}

static void nf_flow_nat_ip(const struct flow_offload *flow, struct sk_buff *skb,
			  unsigned int thoff, enum flow_offload_tuple_dir dir,
			  struct iphdr *iph)
{
	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		nf_flow_snat_port(flow, skb, thoff, iph->protocol, dir);
		nf_flow_snat_ip(flow, skb, iph, thoff, dir);
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		nf_flow_dnat_port(flow, skb, thoff, iph->protocol, dir);
		nf_flow_dnat_ip(flow, skb, iph, thoff, dir);
	}
}

static bool ip_has_options(unsigned int thoff)
{
	return thoff != sizeof(struct iphdr);
}

static void nf_flow_tuple_encap(struct sk_buff *skb,
				struct flow_offload_tuple *tuple)
{
	struct vlan_ethhdr *veth;
	struct pppoe_hdr *phdr;
	int i = 0;

	if (skb_vlan_tag_present(skb)) {
		tuple->encap[i].id = skb_vlan_tag_get(skb);
		tuple->encap[i].proto = skb->vlan_proto;
		i++;
	}
	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		tuple->encap[i].id = ntohs(veth->h_vlan_TCI);
		tuple->encap[i].proto = skb->protocol;
		break;
	case htons(ETH_P_PPP_SES):
		phdr = (struct pppoe_hdr *)skb_mac_header(skb);
		tuple->encap[i].id = ntohs(phdr->sid);
		tuple->encap[i].proto = skb->protocol;
		break;
	}
}

struct nf_flowtable_ctx {
	const struct net_device	*in;
	u32			offset;
	u32			hdrsize;
};

static int nf_flow_tuple_ip(struct nf_flowtable_ctx *ctx, struct sk_buff *skb,
			    struct flow_offload_tuple *tuple)
{
	struct flow_ports *ports;
	unsigned int thoff;
	struct iphdr *iph;
	u8 ipproto;

	if (!pskb_may_pull(skb, sizeof(*iph) + ctx->offset))
		return -1;

	iph = (struct iphdr *)(skb_network_header(skb) + ctx->offset);
	thoff = (iph->ihl * 4);

	if (ip_is_fragment(iph) ||
	    unlikely(ip_has_options(thoff)))
		return -1;

	thoff += ctx->offset;

	ipproto = iph->protocol;
	switch (ipproto) {
	case IPPROTO_TCP:
		ctx->hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		ctx->hdrsize = sizeof(struct udphdr);
		break;
#ifdef CONFIG_NF_CT_PROTO_GRE
	case IPPROTO_GRE:
		ctx->hdrsize = sizeof(struct gre_base_hdr);
		break;
#endif
	default:
		return -1;
	}

	if (iph->ttl <= 1)
		return -1;

	if (!pskb_may_pull(skb, thoff + ctx->hdrsize))
		return -1;

	switch (ipproto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ports = (struct flow_ports *)(skb_network_header(skb) + thoff);
		tuple->src_port		= ports->source;
		tuple->dst_port		= ports->dest;
		break;
	case IPPROTO_GRE: {
		struct gre_base_hdr *greh;

		greh = (struct gre_base_hdr *)(skb_network_header(skb) + thoff);
		if ((greh->flags & GRE_VERSION) != GRE_VERSION_0)
			return -1;
		break;
	}
	}

	iph = (struct iphdr *)(skb_network_header(skb) + ctx->offset);

	tuple->src_v4.s_addr	= iph->saddr;
	tuple->dst_v4.s_addr	= iph->daddr;
	tuple->l3proto		= AF_INET;
	tuple->l4proto		= ipproto;
	tuple->iifidx		= ctx->in->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 0;
}

/* Based on ip_exceeds_mtu(). */
static bool nf_flow_exceeds_mtu(const struct sk_buff *skb, unsigned int mtu)
{
	if (skb->len <= mtu)
		return false;

	if (skb_is_gso(skb) && skb_gso_validate_network_len(skb, mtu))
		return false;

	return true;
}

static inline bool nf_flow_dst_check(struct flow_offload_tuple *tuple)
{
	if (tuple->xmit_type != FLOW_OFFLOAD_XMIT_NEIGH &&
	    tuple->xmit_type != FLOW_OFFLOAD_XMIT_XFRM)
		return true;

	return dst_check(tuple->dst_cache, tuple->dst_cookie);
}

static unsigned int nf_flow_xmit_xfrm(struct sk_buff *skb,
				      const struct nf_hook_state *state,
				      struct dst_entry *dst)
{
	skb_orphan(skb);
	skb_dst_set_noref(skb, dst);
	dst_output(state->net, state->sk, skb);
	return NF_STOLEN;
}

static bool nf_flow_skb_encap_protocol(const struct sk_buff *skb, __be16 proto,
				       u32 *offset)
{
	struct vlan_ethhdr *veth;

	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		if (veth->h_vlan_encapsulated_proto == proto) {
			*offset += VLAN_HLEN;
			return true;
		}
		break;
	case htons(ETH_P_PPP_SES):
		if (nf_flow_pppoe_proto(skb) == proto) {
			*offset += PPPOE_SES_HLEN;
			return true;
		}
		break;
	}

	return false;
}

static void nf_flow_encap_pop(struct sk_buff *skb,
			      struct flow_offload_tuple_rhash *tuplehash)
{
	struct vlan_hdr *vlan_hdr;
	int i;

	for (i = 0; i < tuplehash->tuple.encap_num; i++) {
		if (skb_vlan_tag_present(skb)) {
			__vlan_hwaccel_clear_tag(skb);
			continue;
		}
		switch (skb->protocol) {
		case htons(ETH_P_8021Q):
			vlan_hdr = (struct vlan_hdr *)skb->data;
			__skb_pull(skb, VLAN_HLEN);
			vlan_set_encap_proto(skb, vlan_hdr);
			skb_reset_network_header(skb);
			break;
		case htons(ETH_P_PPP_SES):
			skb->protocol = nf_flow_pppoe_proto(skb);
			skb_pull(skb, PPPOE_SES_HLEN);
			skb_reset_network_header(skb);
			break;
		}
	}
}

static unsigned int nf_flow_queue_xmit(struct net *net, struct sk_buff *skb,
				       const struct flow_offload_tuple_rhash *tuplehash,
				       unsigned short type)
{
	struct net_device *outdev;

	outdev = dev_get_by_index_rcu(net, tuplehash->tuple.out.ifidx);
	if (!outdev)
		return NF_DROP;

	skb->dev = outdev;
	dev_hard_header(skb, skb->dev, type, tuplehash->tuple.out.h_dest,
			tuplehash->tuple.out.h_source, skb->len);
	dev_queue_xmit(skb);

	return NF_STOLEN;
}

static struct flow_offload_tuple_rhash *
nf_flow_offload_lookup(struct nf_flowtable_ctx *ctx,
		       struct nf_flowtable *flow_table, struct sk_buff *skb)
{
	struct flow_offload_tuple tuple = {};

	if (skb->protocol != htons(ETH_P_IP) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IP), &ctx->offset))
		return NULL;

	if (nf_flow_tuple_ip(ctx, skb, &tuple) < 0)
		return NULL;

	return flow_offload_lookup(flow_table, &tuple);
}

static int nf_flow_offload_forward(struct nf_flowtable_ctx *ctx,
				   struct nf_flowtable *flow_table,
				   struct flow_offload_tuple_rhash *tuplehash,
				   struct sk_buff *skb)
{
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	unsigned int thoff, mtu;
	struct iphdr *iph;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + ctx->offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return 0;

	iph = (struct iphdr *)(skb_network_header(skb) + ctx->offset);
	thoff = (iph->ihl * 4) + ctx->offset;
	if (nf_flow_state_check(flow, iph->protocol, skb, thoff))
		return 0;

	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return 0;
	}

	if (skb_try_make_writable(skb, thoff + ctx->hdrsize))
		return -1;

	flow_offload_refresh(flow_table, flow, false);

	nf_flow_encap_pop(skb, tuplehash);
	thoff -= ctx->offset;

	iph = ip_hdr(skb);
	nf_flow_nat_ip(flow, skb, thoff, dir, iph);

	ip_decrease_ttl(iph);
	skb_clear_tstamp(skb);

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	return 1;
}

static void nft_bulk_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct dst_entry *dst;
	struct xfrm_state *x;
	struct sk_buff *p;
	struct rtable *rt;
	__be32 daddr;
	int proto;
	__u8 tos;

	iph = ip_hdr(skb);
	dst = skb_dst(skb);
	BUG_ON(!dst);

	rt = (struct rtable *)dst;
	daddr = rt_nexthop(rt, iph->daddr);
	x = dst_xfrm(dst);
	proto = iph->protocol;
	tos = iph->tos;

	list_for_each_entry(p, head, list) {
		struct dst_entry *dst2;
		struct rtable *rt2;
		struct iphdr *iph2;
		__be32 daddr2;

		if (p->protocol != htons(ETH_P_IP))
			continue;

		dst2 = skb_dst(p);
		rt2 = (struct rtable *)dst2;
		if (dst->dev != dst2->dev)
			continue;

		iph2 = ip_hdr(p);
		daddr2 = rt_nexthop(rt2, iph2->daddr);
		if (daddr != daddr2)
			continue;

		if (tos != iph2->tos)
			continue;

		if (x != dst_xfrm(dst2))
			continue;

		goto found;
	}

	goto out;

found:
	if (NFT_BULK_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NFT_BULK_CB(p)->last->next = skb;

	NFT_BULK_CB(p)->last = skb;

	return;
out:
	/* First skb */
	NFT_BULK_CB(skb)->last = skb;
	list_add_tail(&skb->list, head);
	skb->priority = rt_tos2priority(iph->tos);

	return;
}

static void nf_flow_neigh_xmit_list(struct sk_buff *skb, struct net_device *outdev, const void *daddr)
{
	struct sk_buff *iter = skb->next;
	int hlen;

	skb->dev = outdev;
	hlen = dev_hard_header(skb, outdev, ntohs(skb->protocol), daddr, NULL, skb->len);
	if (hlen < 0) {
		kfree_skb_list(skb);
		return;
	}

	skb_reset_mac_header(skb);

	while (iter) {
		iter->dev = outdev;
		skb_push(iter, hlen);
		skb_copy_to_linear_data(iter, skb->data, hlen);
		skb_reset_mac_header(iter);
		iter = iter->next;
	}

	if (dev_queue_xmit_list(skb) == -1) {
		iter = skb;
		while (iter) {
			struct sk_buff *next;

			next = iter->next;
			iter->next = NULL;
			dev_queue_xmit(iter);
			iter = next;
		}
	}
}

void __nf_flow_offload_ip_hook_list(void *priv, struct list_head *head,
				    const struct net_device *in)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct nf_flowtable_ctx ctx = {
		.in	= in,
	};
	struct list_head *bulk_head;
	struct sk_buff *skb, *n;
	struct neighbour *neigh;
	LIST_HEAD(bulk_list);
	LIST_HEAD(acc_list);
	struct rtable *rt;
	int ret;

	preempt_disable();
	bulk_head = this_cpu_ptr(flow_table->bulk_list);

	list_for_each_entry_safe(skb, n, head, list) {
		skb_list_del_init(skb);

		ctx.hdrsize = 0;
		ctx.offset = 0;

		tuplehash = nf_flow_offload_lookup(&ctx, flow_table, skb);
		if (!tuplehash) {
			list_add_tail(&skb->list, &acc_list);
			continue;
		}

		ret = nf_flow_offload_forward(&ctx, flow_table, tuplehash, skb);
		if (ret < 0) {
			kfree_skb(skb);
			continue;
		} else if (ret == 0) {
			list_add_tail(&skb->list, &acc_list);
			continue;
		}

		skb_dst_set_noref(skb, tuplehash->tuple.dst_cache);
		memset(skb->cb, 0, sizeof(struct nft_bulk_cb));
		NFT_BULK_CB(skb)->tuplehash = tuplehash;

		list_add_tail(&skb->list, &bulk_list);
	}

	list_splice_init(&acc_list, head);

	list_for_each_entry_safe(skb, n, &bulk_list, list) {
		skb_list_del_init(skb);
		nft_bulk_receive(bulk_head, skb);
	}

	list_for_each_entry_safe(skb, n, bulk_head, list) {

		list_del_init(&skb->list);

		skb->next = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;

		tuplehash = NFT_BULK_CB(skb)->tuplehash;
		skb_dst_set_noref(skb, tuplehash->tuple.dst_cache);
		rt = (struct rtable *)skb_dst(skb);

		neigh = ip_neigh_gw4(rt->dst.dev, rt_nexthop(rt, ip_hdr(skb)->daddr));
		if (IS_ERR(neigh)) {
			kfree_skb_list(skb);
			continue;
		}

		nf_flow_neigh_xmit_list(skb, rt->dst.dev, neigh->ha);
	}
	preempt_enable();

	BUG_ON(!list_empty(bulk_head));
}
EXPORT_SYMBOL_GPL(__nf_flow_offload_ip_hook_list);

unsigned int
nf_flow_offload_ip_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	enum flow_offload_tuple_dir dir;
	struct nf_flowtable_ctx ctx = {
		.in	= state->in,
	};
	struct flow_offload *flow;
	struct net_device *outdev;
	struct rtable *rt;
	__be32 nexthop;
	int ret;

	tuplehash = nf_flow_offload_lookup(&ctx, flow_table, skb);
	if (!tuplehash)
		return NF_ACCEPT;

	ret = nf_flow_offload_forward(&ctx, flow_table, tuplehash, skb);
	if (ret < 0)
		return NF_DROP;
	else if (ret == 0)
		return NF_ACCEPT;

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet_skb_parm));
		IPCB(skb)->iif = skb->dev->ifindex;
		IPCB(skb)->flags = IPSKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		outdev = rt->dst.dev;
		skb->dev = outdev;
		nexthop = rt_nexthop(rt, flow->tuplehash[!dir].tuple.src_v4.s_addr);
		skb_dst_set_noref(skb, &rt->dst);
		neigh_xmit(NEIGH_ARP_TABLE, outdev, &nexthop, skb);
		ret = NF_STOLEN;
		break;
	case FLOW_OFFLOAD_XMIT_DIRECT:
		ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IP);
		if (ret == NF_DROP)
			flow_offload_teardown(flow);
		break;
	default:
		WARN_ON_ONCE(1);
		ret = NF_DROP;
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ip_hook);

static void nf_flow_nat_ipv6_tcp(struct sk_buff *skb, unsigned int thoff,
				 struct in6_addr *addr,
				 struct in6_addr *new_addr,
				 struct ipv6hdr *ip6h)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace16(&tcph->check, skb, addr->s6_addr32,
				  new_addr->s6_addr32, true);
}

static void nf_flow_nat_ipv6_udp(struct sk_buff *skb, unsigned int thoff,
				 struct in6_addr *addr,
				 struct in6_addr *new_addr)
{
	struct udphdr *udph;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace16(&udph->check, skb, addr->s6_addr32,
					  new_addr->s6_addr32, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}
}

static void nf_flow_nat_ipv6_l4proto(struct sk_buff *skb, struct ipv6hdr *ip6h,
				     unsigned int thoff, struct in6_addr *addr,
				     struct in6_addr *new_addr)
{
	switch (ip6h->nexthdr) {
	case IPPROTO_TCP:
		nf_flow_nat_ipv6_tcp(skb, thoff, addr, new_addr, ip6h);
		break;
	case IPPROTO_UDP:
		nf_flow_nat_ipv6_udp(skb, thoff, addr, new_addr);
		break;
	}
}

static void nf_flow_snat_ipv6(const struct flow_offload *flow,
			      struct sk_buff *skb, struct ipv6hdr *ip6h,
			      unsigned int thoff,
			      enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.dst_v6;
		ip6h->saddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.src_v6;
		ip6h->daddr = new_addr;
		break;
	}

	nf_flow_nat_ipv6_l4proto(skb, ip6h, thoff, &addr, &new_addr);
}

static void nf_flow_dnat_ipv6(const struct flow_offload *flow,
			      struct sk_buff *skb, struct ipv6hdr *ip6h,
			      unsigned int thoff,
			      enum flow_offload_tuple_dir dir)
{
	struct in6_addr addr, new_addr;

	switch (dir) {
	case FLOW_OFFLOAD_DIR_ORIGINAL:
		addr = ip6h->daddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.src_v6;
		ip6h->daddr = new_addr;
		break;
	case FLOW_OFFLOAD_DIR_REPLY:
		addr = ip6h->saddr;
		new_addr = flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.dst_v6;
		ip6h->saddr = new_addr;
		break;
	}

	nf_flow_nat_ipv6_l4proto(skb, ip6h, thoff, &addr, &new_addr);
}

static void nf_flow_nat_ipv6(const struct flow_offload *flow,
			     struct sk_buff *skb,
			     enum flow_offload_tuple_dir dir,
			     struct ipv6hdr *ip6h)
{
	unsigned int thoff = sizeof(*ip6h);

	if (test_bit(NF_FLOW_SNAT, &flow->flags)) {
		nf_flow_snat_port(flow, skb, thoff, ip6h->nexthdr, dir);
		nf_flow_snat_ipv6(flow, skb, ip6h, thoff, dir);
	}
	if (test_bit(NF_FLOW_DNAT, &flow->flags)) {
		nf_flow_dnat_port(flow, skb, thoff, ip6h->nexthdr, dir);
		nf_flow_dnat_ipv6(flow, skb, ip6h, thoff, dir);
	}
}

static int nf_flow_tuple_ipv6(struct nf_flowtable_ctx *ctx, struct sk_buff *skb,
			      struct flow_offload_tuple *tuple)
{
	struct flow_ports *ports;
	struct ipv6hdr *ip6h;
	unsigned int thoff;
	u8 nexthdr;

	thoff = sizeof(*ip6h) + ctx->offset;
	if (!pskb_may_pull(skb, thoff))
		return -1;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + ctx->offset);

	nexthdr = ip6h->nexthdr;
	switch (nexthdr) {
	case IPPROTO_TCP:
		ctx->hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		ctx->hdrsize = sizeof(struct udphdr);
		break;
#ifdef CONFIG_NF_CT_PROTO_GRE
	case IPPROTO_GRE:
		ctx->hdrsize = sizeof(struct gre_base_hdr);
		break;
#endif
	default:
		return -1;
	}

	if (ip6h->hop_limit <= 1)
		return -1;

	if (!pskb_may_pull(skb, thoff + ctx->hdrsize))
		return -1;

	switch (nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		ports = (struct flow_ports *)(skb_network_header(skb) + thoff);
		tuple->src_port		= ports->source;
		tuple->dst_port		= ports->dest;
		break;
	case IPPROTO_GRE: {
		struct gre_base_hdr *greh;

		greh = (struct gre_base_hdr *)(skb_network_header(skb) + thoff);
		if ((greh->flags & GRE_VERSION) != GRE_VERSION_0)
			return -1;
		break;
	}
	}

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + ctx->offset);

	tuple->src_v6		= ip6h->saddr;
	tuple->dst_v6		= ip6h->daddr;
	tuple->l3proto		= AF_INET6;
	tuple->l4proto		= nexthdr;
	tuple->iifidx		= ctx->in->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 0;
}

static int nf_flow_offload_ipv6_forward(struct nf_flowtable_ctx *ctx,
					struct nf_flowtable *flow_table,
					struct flow_offload_tuple_rhash *tuplehash,
					struct sk_buff *skb)
{
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	unsigned int thoff, mtu;
	struct ipv6hdr *ip6h;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + ctx->offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return 0;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + ctx->offset);
	thoff = sizeof(*ip6h) + ctx->offset;
	if (nf_flow_state_check(flow, ip6h->nexthdr, skb, thoff))
		return 0;

	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return 0;
	}

	if (skb_try_make_writable(skb, thoff + ctx->hdrsize))
		return -1;

	flow_offload_refresh(flow_table, flow, false);

	nf_flow_encap_pop(skb, tuplehash);

	ip6h = ipv6_hdr(skb);
	nf_flow_nat_ipv6(flow, skb, dir, ip6h);

	ip6h->hop_limit--;
	skb_clear_tstamp(skb);

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	return 1;
}

static struct flow_offload_tuple_rhash *
nf_flow_offload_ipv6_lookup(struct nf_flowtable_ctx *ctx,
			    struct nf_flowtable *flow_table,
			    struct sk_buff *skb)
{
	struct flow_offload_tuple tuple = {};

	if (skb->protocol != htons(ETH_P_IPV6) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IPV6), &ctx->offset))
		return NULL;

	if (nf_flow_tuple_ipv6(ctx, skb, &tuple) < 0)
		return NULL;

	return flow_offload_lookup(flow_table, &tuple);
}

unsigned int
nf_flow_offload_ipv6_hook(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	enum flow_offload_tuple_dir dir;
	struct nf_flowtable_ctx ctx = {
		.in	= state->in,
	};
	const struct in6_addr *nexthop;
	struct flow_offload *flow;
	struct net_device *outdev;
	struct rt6_info *rt;
	int ret;

	tuplehash = nf_flow_offload_ipv6_lookup(&ctx, flow_table, skb);
	if (tuplehash == NULL)
		return NF_ACCEPT;

	ret = nf_flow_offload_ipv6_forward(&ctx, flow_table, tuplehash, skb);
	if (ret < 0)
		return NF_DROP;
	else if (ret == 0)
		return NF_ACCEPT;

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
		IP6CB(skb)->iif = skb->dev->ifindex;
		IP6CB(skb)->flags = IP6SKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	switch (tuplehash->tuple.xmit_type) {
	case FLOW_OFFLOAD_XMIT_NEIGH:
		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		outdev = rt->dst.dev;
		skb->dev = outdev;
		nexthop = rt6_nexthop(rt, &flow->tuplehash[!dir].tuple.src_v6);
		skb_dst_set_noref(skb, &rt->dst);
		neigh_xmit(NEIGH_ND_TABLE, outdev, nexthop, skb);
		ret = NF_STOLEN;
		break;
	case FLOW_OFFLOAD_XMIT_DIRECT:
		ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IPV6);
		if (ret == NF_DROP)
			flow_offload_teardown(flow);
		break;
	default:
		WARN_ON_ONCE(1);
		ret = NF_DROP;
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ipv6_hook);

static void nft_bulk_ipv6_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct in6_addr *daddr;
	const struct ipv6hdr *ip6h;
	struct dst_entry *dst;
	struct xfrm_state *x;
	struct rt6_info *rt;
	struct sk_buff *p;
	int proto;

	ip6h = ipv6_hdr(skb);
	dst = skb_dst(skb);
	BUG_ON(!dst);

	rt = (struct rt6_info *)dst;
	daddr = rt6_nexthop(rt, &ip6h->daddr);
	x = dst_xfrm(dst);
	proto = ip6h->nexthdr;

	list_for_each_entry(p, head, list) {
		const struct in6_addr *daddr2;
		struct dst_entry *dst2;
		struct ipv6hdr *ip6h2;
		struct rt6_info *rt2;

		if (p->protocol != htons(ETH_P_IPV6))
			continue;

		dst2 = skb_dst(p);
		rt2 = (struct rt6_info *)dst2;
		if (dst->dev != dst2->dev)
			continue;

		ip6h2 = ipv6_hdr(p);
		daddr2 = rt6_nexthop(rt2, &ip6h2->daddr);
		if (!ipv6_addr_equal(daddr, daddr2))
			continue;

		if (x != dst_xfrm(dst2))
			continue;

		goto found;
	}

	goto out;

found:
	if (NFT_BULK_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NFT_BULK_CB(p)->last->next = skb;

	NFT_BULK_CB(p)->last = skb;

	return;
out:
	/* First skb */
	NFT_BULK_CB(skb)->last = skb;
	list_add_tail(&skb->list, head);

	return;

}

void __nf_flow_offload_ipv6_hook_list(void *priv, struct list_head *head,
				      const struct net_device *in)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct nf_flowtable_ctx ctx = {
		.in	= in,
	};
	struct list_head *bulk_head;
	struct sk_buff *skb, *n;
	struct neighbour *neigh;
	LIST_HEAD(bulk_list);
	LIST_HEAD(acc_list);
	struct rt6_info *rt;
	int ret;

	preempt_disable();
	bulk_head = this_cpu_ptr(flow_table->bulk_list);

	list_for_each_entry_safe(skb, n, head, list) {
		skb_list_del_init(skb);

		ctx.hdrsize = 0;
		ctx.offset = 0;

		tuplehash = nf_flow_offload_ipv6_lookup(&ctx, flow_table, skb);
		if (!tuplehash) {
			list_add_tail(&skb->list, &acc_list);
			continue;
		}

		ret = nf_flow_offload_ipv6_forward(&ctx, flow_table, tuplehash, skb);
		if (ret < 0) {
			kfree_skb(skb);
			continue;
		} else if (ret == 0) {
			list_add_tail(&skb->list, &acc_list);
			continue;
		}

		skb_dst_set_noref(skb, tuplehash->tuple.dst_cache);
		memset(skb->cb, 0, sizeof(struct nft_bulk_cb));
		NFT_BULK_CB(skb)->tuplehash = tuplehash;

		list_add_tail(&skb->list, &bulk_list);
	}

	list_splice_init(&acc_list, head);

	list_for_each_entry_safe(skb, n, &bulk_list, list) {
		skb_list_del_init(skb);
		nft_bulk_ipv6_receive(bulk_head, skb);
	}

	list_for_each_entry_safe(skb, n, bulk_head, list) {

		list_del_init(&skb->list);

		skb->next = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;

		tuplehash = NFT_BULK_CB(skb)->tuplehash;
		skb_dst_set_noref(skb, tuplehash->tuple.dst_cache);
		rt = (struct rt6_info *)skb_dst(skb);

		neigh = ip_neigh_gw6(rt->dst.dev, rt6_nexthop(rt, &ipv6_hdr(skb)->daddr));
		if (IS_ERR(neigh)) {
			kfree_skb_list(skb);
			continue;
		}

		nf_flow_neigh_xmit_list(skb, rt->dst.dev, neigh->ha);
	}
	preempt_enable();

	BUG_ON(!list_empty(bulk_head));
}
EXPORT_SYMBOL_GPL(__nf_flow_offload_ipv6_hook_list);
