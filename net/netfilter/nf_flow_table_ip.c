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
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/neighbour.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include <net/xfrm.h>
#include <net/pkt_sched.h>
#include <net/esp.h>
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

static int nf_flow_tuple_ip(struct sk_buff *skb, const struct net_device *dev,
			    struct flow_offload_tuple *tuple, u32 *hdrsize,
			    u32 offset)
{
	struct flow_ports *ports;
	unsigned int thoff;
	struct iphdr *iph;

	if (!pskb_may_pull(skb, sizeof(*iph) + offset))
		return 0;

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	thoff = (iph->ihl * 4);

	if (ip_is_fragment(iph) ||
	    unlikely(ip_has_options(thoff)))
		return -1;

	thoff += offset;

	switch (iph->protocol) {
	case IPPROTO_TCP:
		*hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		*hdrsize = sizeof(struct udphdr);
		break;
	case IPPROTO_ESP:
		*hdrsize = sizeof(struct ip_esp_hdr);
		break;
	default:
		return 0;
	}

	if (iph->ttl <= 1)
		return 0;

	if (!pskb_may_pull(skb, thoff + *hdrsize))
		return 0;

	if ((iph->protocol == IPPROTO_ESP)) {
		skb_pull(skb, offset);
		skb_reset_network_header(skb);
		skb_set_transport_header(skb, thoff);
		return 2;
	}

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);

	tuple->src_v4.s_addr	= iph->saddr;
	tuple->dst_v4.s_addr	= iph->daddr;
	tuple->src_port		= ports->source;
	tuple->dst_port		= ports->dest;
	tuple->l3proto		= AF_INET;
	tuple->l4proto		= iph->protocol;
	tuple->iifidx		= dev->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 1;
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

static inline __be16 nf_flow_pppoe_proto(const struct sk_buff *skb)
{
	__be16 proto;

	proto = *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
			     sizeof(struct pppoe_hdr)));
	switch (proto) {
	case htons(PPP_IP):
		return htons(ETH_P_IP);
	case htons(PPP_IPV6):
		return htons(ETH_P_IPV6);
	}

	return 0;
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

/*
int nft_bulk_receive_list(struct sk_buff *p, struct sk_buff *skb)
{
	NFT_BULK_CB(p)->last->next = skb;
	NFT_BULK_CB(p)->last = skb;

	return 0;
}
*/

static int nft_esp_bulk_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct sk_buff *p;
	struct xfrm_state *x;
	struct sec_path *sp;
	__be32 daddr;
	__be32 spi;

	if (xfrm_offload(skb))
		return -EINVAL;

	iph = ip_hdr(skb);
	daddr = iph->daddr;

	BUG_ON(iph->protocol != IPPROTO_ESP);

	spi = ip_esp_hdr(skb)->spi;

	XFRM_SPI_SKB_CB(skb)->family = AF_INET;
	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct iphdr, daddr);
	XFRM_SPI_SKB_CB(skb)->seq = ip_esp_hdr(skb)->seq_no;
	XFRM_SPI_SKB_CB(skb)->spi = spi;

	list_for_each_entry(p, head, list) {

		if (daddr != ip_hdr(p)->daddr) {
			continue;
		}

		if (spi != ip_esp_hdr(p)->spi) {
			continue;
		}

		goto found;
	}

	goto out;

found:
	if (NFT_BULK_CB(p)->last == p)
		skb_shinfo(p)->frag_list = skb;
	else
		NFT_BULK_CB(p)->last->next = skb;

	NFT_BULK_CB(p)->last = skb;
	skb_pull(skb, sizeof(*iph));
	/* XXX: Copy or alloc new one? */
	__skb_ext_copy(skb, p);

	return 0;
out:
	/* First skb */
	NFT_BULK_CB(skb)->last = skb;
	list_add_tail(&skb->list, head);

	x = xfrm_state_lookup(dev_net(skb->dev), skb->mark,
			(xfrm_address_t *)&daddr,
			spi, IPPROTO_ESP, AF_INET);
	if (!x)
		return -ENOENT;

	sp = secpath_set(skb);
	if (!sp)
		return -ENOMEM;

	sp->xvec[sp->len++] = x;
	skb_pull(skb, sizeof(*iph));
	skb->priority = rt_tos2priority(iph->tos);

	return 0;
}


static void nft_bulk_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct iphdr *iph;
	struct sk_buff *p;
	struct dst_entry *dst;
	struct rtable *rt;
	struct xfrm_state *x;
	int proto;
	__be32 daddr;
	__u8 tos;

	iph = ip_hdr(skb);
	dst = skb_dst(skb);
	/* dst must be present from the flowtable
	if (!dst) {
		goto out;
	}
	*/

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

		dst2 = skb_dst(p);
		rt2 = (struct rtable *)dst2;
		if (dst->dev != dst2->dev) {
			continue;
		}

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

unsigned int
__nf_flow_offload_ip_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct flow_offload_tuple tuple = {};
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	u32 hdrsize, offset = 0;
	unsigned int thoff, mtu;
	struct iphdr *iph;
	struct dst_entry *dst;
	int ret;

	skb_reset_network_header(skb);
	if (!skb_transport_header_was_set(skb))
		skb_reset_transport_header(skb);
	skb_reset_mac_len(skb);

	prefetchw(skb_network_header(skb));

	if (skb->protocol != htons(ETH_P_IP) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IP), &offset))
		return 0;

	ret = nf_flow_tuple_ip(skb, state->in, &tuple, &hdrsize, offset);
	if (ret != 1)
		return ret;

	tuplehash = flow_offload_lookup(flow_table, &tuple);
	if (tuplehash == NULL)
		return 0;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return 0;

	iph = (struct iphdr *)(skb_network_header(skb) + offset);
	thoff = (iph->ihl * 4) + offset;
	if (nf_flow_state_check(flow, iph->protocol, skb, thoff))
		return 0;

	dst = tuplehash->tuple.dst_cache;
	skb_dst_set_noref(skb, dst);

	/* FIXME: Can't bulk, but flowtable offload is possible! */
	if ((dst->xfrm && !xfrm_dev_offload_ok(skb, dst->xfrm)) ||
	    skb_is_gso(skb))
		return 0;

	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return NF_ACCEPT;
	}

	if (skb_try_make_writable(skb, thoff + hdrsize))
		return -1;
	
	memset(skb->cb, 0, sizeof(struct nft_bulk_cb));
	NFT_BULK_CB(skb)->tuplehash = tuplehash;

	flow_offload_refresh(flow_table, flow);

	nf_flow_encap_pop(skb, tuplehash);
	thoff -= offset;

	iph = ip_hdr(skb);
	nf_flow_nat_ip(flow, skb, thoff, dir, iph);

	ip_decrease_ttl(iph);
	skb->tstamp = 0;

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	return 1;
}

static int nft_qdisc_enqueue(struct sk_buff *skb, struct Qdisc *q,
			     struct netdev_queue *txq, struct sk_buff **to_free)
{
	struct sk_buff *iter;
	int rc;

	iter = skb;

	while (iter) {
		struct sk_buff *next = iter->next;
		iter->next = NULL;

		qdisc_pkt_len_init(iter);
		qdisc_calculate_pkt_len(iter, q);
		rc = q->enqueue(iter, q, to_free) & NET_XMIT_MASK;

		iter = next;
	}

	return NET_XMIT_SUCCESS;
}

static inline int nft_dev_xmit_skb(struct sk_buff *skb, struct Qdisc *q,
				 struct net_device *dev,
				 struct netdev_queue *txq)
{
	struct sk_buff *to_free = NULL;
	int rc;

	if (q->flags & TCQ_F_NOLOCK) {
		if (q->flags & TCQ_F_CAN_BYPASS && nolock_qdisc_is_empty(q) &&
		    qdisc_run_begin(q)) {
			/* Retest nolock_qdisc_is_empty() within the protection
			 * of q->seqlock to protect from racing with requeuing.
			 */
			if (unlikely(!nolock_qdisc_is_empty(q))) {
				rc = nft_qdisc_enqueue(skb, q, txq, &to_free);
				__qdisc_run(q);
				qdisc_run_end(q);

				goto out;
			}

			if (sch_direct_xmit(skb, q, dev, txq, NULL, false) &&
			    !nolock_qdisc_is_empty(q))
				__qdisc_run(q);

			qdisc_run_end(q);
			return NET_XMIT_SUCCESS;
		}

		rc = nft_qdisc_enqueue(skb, q, txq, &to_free);
		qdisc_run(q);

out:
		if (unlikely(to_free))
			kfree_skb_list(to_free);


		return rc;
	}

	return -1;
}

static int nft_dev_queue_xmit(struct sk_buff *skb)
{
	struct net_device *dev = skb->dev;
	struct netdev_queue *txq;
	struct sk_buff *iter;
	struct Qdisc *q;
	int rc = -ENOMEM;
	bool again = false;

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_SCHED_TSTAMP))
		return -1;

	/* Disable soft irqs for various locks below. Also
	 * stops preemption for RCU.
	 */
	rcu_read_lock_bh();

/* FIXME: egress_needed_key is defined static in net/core/dev.c */
//# ifdef CONFIG_NET_EGRESS
//	if (static_branch_unlikely(&egress_needed_key))
//		return -1;
//# endif

	txq = netdev_core_pick_tx(dev, skb, NULL);
	q = rcu_dereference_bh(txq->qdisc);

	iter = skb;
	while (iter) {
		/* If device/qdisc don't need skb->dst, release it right now while
		 * its hot in this cpu cache.
		 */
		if (dev->priv_flags & IFF_XMIT_DST_RELEASE)
			skb_dst_drop(iter);
		else
			skb_dst_force(iter);

		skb_copy_queue_mapping(iter, skb);

		iter = iter->next;
	}

	if (q->enqueue) {
		rc = nft_dev_xmit_skb(skb, q, dev, txq);
		goto out;
	}

	/* The device has no queue. Common case for software devices:
	 * loopback, all the sorts of tunnels...

	 * Really, it is unlikely that netif_tx_lock protection is necessary
	 * here.  (f.e. loopback and IP tunnels are clean ignoring statistics
	 * counters.)
	 * However, it is possible, that they rely on protection
	 * made by us here.

	 * Check this and shot the lock. It is not prone from deadlocks.
	 *Either shot noqueue qdisc, it is even simpler 8)
	 */
	
	if (dev->flags & IFF_UP) {
		int cpu = smp_processor_id();

		if (txq->xmit_lock_owner != cpu) {
			if (dev_xmit_recursion())
				goto recursion_alert;

			skb = validate_xmit_skb_list(skb, dev, &again);
			if (!skb)
				goto out;

			PRANDOM_ADD_NOISE(skb, dev, txq, jiffies);
			HARD_TX_LOCK(dev, txq, cpu);

			if (!netif_xmit_stopped(txq)) {
				dev_xmit_recursion_inc();
				skb = dev_hard_start_xmit(skb, dev, txq, &rc);
				dev_xmit_recursion_dec();
				if (dev_xmit_complete(rc)) {
					HARD_TX_UNLOCK(dev, txq);
					goto out;
				}
			}
			HARD_TX_UNLOCK(dev, txq);
			net_crit_ratelimited("Virtual device %s asks to queue packet!\n",
					     dev->name);
		} else {
recursion_alert:
			net_crit_ratelimited("Dead loop on virtual device %s, fix it urgently!\n",
					     dev->name);
		}
	}

	rc = -ENETDOWN;
	rcu_read_unlock_bh();

	/* FIXME: For each skb!!! */
	atomic_long_inc(&dev->tx_dropped);
	kfree_skb_list(skb);
	return rc;
out:
	rcu_read_unlock_bh();
	return rc;
}

static void nf_flow_neigh_xmit_list(struct sk_buff *skb, struct net_device *outdev, const void *daddr)
{
	struct sk_buff *iter = skb->next;
	int hlen;

	skb->dev = outdev;
	hlen = dev_hard_header(skb, outdev, ETH_P_IP, daddr, NULL, skb->len);
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


	if (nft_dev_queue_xmit(skb) == -1) {
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

unsigned int
nf_flow_offload_ip_hook_list(void *priv, struct sk_buff *unused,
			const struct nf_hook_state *state)
{
	struct nf_flowtable *flow_table = priv;
	struct rtable *rt;
	int ret, cpu;
	struct sk_buff *skb, *n;
	struct list_head bulk_list;
	struct list_head acc_list;
	struct list_head esp_list;
	struct list_head *bulk_head;
	struct list_head *head = state->skb_list;
	struct neighbour *neigh;


	cpu = get_cpu();

	INIT_LIST_HEAD(&bulk_list);
	INIT_LIST_HEAD(&acc_list);
	INIT_LIST_HEAD(&esp_list);

	bulk_head = per_cpu_ptr(flow_table->bulk_list, cpu);

	list_for_each_entry_safe(skb, n, head, list) {

		skb_list_del_init(skb);
		ret = __nf_flow_offload_ip_hook(priv, skb, state);
		if (ret == 0)
			list_add_tail(&skb->list, &acc_list);
		else if (ret == 1)
			list_add_tail(&skb->list, &bulk_list);
		else if (ret == 2)
			list_add_tail(&skb->list, &esp_list);
		/* ret == -1: Packet dropped! */
		else if (ret == -1)
			kfree_skb(skb);

	}

	list_for_each_entry_safe(skb, n, &esp_list, list) {
		skb_list_del_init(skb);
		memset(skb->cb, 0, sizeof(struct nft_bulk_cb));
		ret = nft_esp_bulk_receive(bulk_head, skb);
		if (ret)
			list_add_tail(&skb->list, &acc_list);
	}

	list_for_each_entry_safe(skb, n, bulk_head, list) {

		list_del_init(&skb->list);

		skb->next = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;

		ret = xfrm_input_list(&skb, IPPROTO_ESP, 0, -2);
		/* Returns always 0 */
	}

	/*XXX: fwd policy check */

	list_splice_init(&acc_list, head);

	list_for_each_entry_safe(skb, n, &bulk_list, list) {
		skb_list_del_init(skb);
		nft_bulk_receive(bulk_head, skb);
	}

	list_for_each_entry_safe(skb, n, bulk_head, list) {

		list_del_init(&skb->list);

		skb->next = skb_shinfo(skb)->frag_list;
		skb_shinfo(skb)->frag_list = NULL;

		if (skb_dst(skb)->xfrm) {
			skb = xfrm_output_list(skb);
			if (!skb)
				continue;
		}

		rt = (struct rtable *)skb_dst(skb);

		/* FIXME: Move out of the loop! */
		neigh = ip_neigh_gw4(rt->dst.dev, rt_nexthop(rt, ip_hdr(skb)->daddr));
		if (!neigh) {
			kfree_skb_list(skb);
			continue;
		}

		nf_flow_neigh_xmit_list(skb, rt->dst.dev, neigh->ha);

/*
		while (skb) {
			struct flow_offload_tuple_rhash *tuplehash;
			enum flow_offload_tuple_dir dir;
			struct flow_offload *flow;
			struct sk_buff *next;

			next = skb->next;
			skb_mark_not_on_list(skb);
			tuplehash = NFT_BULK_CB(skb)->tuplehash;

			switch (tuplehash->tuple.xmit_type) {
			case FLOW_OFFLOAD_XMIT_NEIGH:
				rt = (struct rtable *)skb_dst(skb);
				outdev = rt->dst.dev;
				skb->dev = outdev;
				nexthop = rt_nexthop(rt, ip_hdr(skb)->saddr);
				neigh_xmit(NEIGH_ARP_TABLE, outdev, &nexthop, skb);
				break;
			case FLOW_OFFLOAD_XMIT_DIRECT:
				dir = tuplehash->tuple.dir;
				flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);
				ret = nf_flow_queue_xmit(state->net, skb, tuplehash, ETH_P_IP);
				if (ret == NF_DROP)
					flow_offload_teardown(flow);
				break;
			case FLOW_OFFLOAD_XMIT_XFRM:
				memset(skb->cb, 0, sizeof(struct inet_skb_parm));
				IPCB(skb)->iif = skb->dev->ifindex;
				IPCB(skb)->flags = IPSKB_FORWARDED;
				nf_flow_xmit_xfrm(skb, state, skb_dst(skb));
				break;
			}

			skb = next;
		}
*/
	}

	put_cpu();

	BUG_ON(!list_empty(bulk_head));

	if (!list_empty(head))
		return NF_ACCEPT;

	/* XXX: What to return here? */
	return NF_STOLEN;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ip_hook_list);


unsigned int
nf_flow_offload_ip_hook(void *priv, struct sk_buff *skb,
			const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	enum flow_offload_tuple_dir dir;
	struct flow_offload *flow;
	struct net_device *outdev;
	struct rtable *rt;
	__be32 nexthop;
	int ret;

	ret = __nf_flow_offload_ip_hook(priv, skb, state);
	if (ret == 0)
		return NF_ACCEPT;	
	else if (ret == -1)
		return NF_DROP;	

	tuplehash = NFT_BULK_CB(skb)->tuplehash;

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rtable *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet_skb_parm));
		IPCB(skb)->iif = skb->dev->ifindex;
		IPCB(skb)->flags = IPSKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

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
	}

	return NF_ACCEPT;
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

static int nf_flow_tuple_ipv6(struct sk_buff *skb, const struct net_device *dev,
			      struct flow_offload_tuple *tuple, u32 *hdrsize,
			      u32 offset)
{
	struct flow_ports *ports;
	struct ipv6hdr *ip6h;
	unsigned int thoff;

	thoff = sizeof(*ip6h) + offset;
	if (!pskb_may_pull(skb, thoff))
		return -1;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);

	switch (ip6h->nexthdr) {
	case IPPROTO_TCP:
		*hdrsize = sizeof(struct tcphdr);
		break;
	case IPPROTO_UDP:
		*hdrsize = sizeof(struct udphdr);
		break;
	default:
		return -1;
	}

	if (ip6h->hop_limit <= 1)
		return -1;

	if (!pskb_may_pull(skb, thoff + *hdrsize))
		return -1;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
	ports = (struct flow_ports *)(skb_network_header(skb) + thoff);

	tuple->src_v6		= ip6h->saddr;
	tuple->dst_v6		= ip6h->daddr;
	tuple->src_port		= ports->source;
	tuple->dst_port		= ports->dest;
	tuple->l3proto		= AF_INET6;
	tuple->l4proto		= ip6h->nexthdr;
	tuple->iifidx		= dev->ifindex;
	nf_flow_tuple_encap(skb, tuple);

	return 0;
}

unsigned int
nf_flow_offload_ipv6_hook(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct flow_offload_tuple_rhash *tuplehash;
	struct nf_flowtable *flow_table = priv;
	struct flow_offload_tuple tuple = {};
	enum flow_offload_tuple_dir dir;
	const struct in6_addr *nexthop;
	struct flow_offload *flow;
	struct net_device *outdev;
	unsigned int thoff, mtu;
	u32 hdrsize, offset = 0;
	struct ipv6hdr *ip6h;
	struct rt6_info *rt;
	int ret;

	if (skb->protocol != htons(ETH_P_IPV6) &&
	    !nf_flow_skb_encap_protocol(skb, htons(ETH_P_IPV6), &offset))
		return NF_ACCEPT;

	if (nf_flow_tuple_ipv6(skb, state->in, &tuple, &hdrsize, offset) < 0)
		return NF_ACCEPT;

	tuplehash = flow_offload_lookup(flow_table, &tuple);
	if (tuplehash == NULL)
		return NF_ACCEPT;

	dir = tuplehash->tuple.dir;
	flow = container_of(tuplehash, struct flow_offload, tuplehash[dir]);

	mtu = flow->tuplehash[dir].tuple.mtu + offset;
	if (unlikely(nf_flow_exceeds_mtu(skb, mtu)))
		return NF_ACCEPT;

	ip6h = (struct ipv6hdr *)(skb_network_header(skb) + offset);
	thoff = sizeof(*ip6h) + offset;
	if (nf_flow_state_check(flow, ip6h->nexthdr, skb, thoff))
		return NF_ACCEPT;

	if (!nf_flow_dst_check(&tuplehash->tuple)) {
		flow_offload_teardown(flow);
		return NF_ACCEPT;
	}

	if (skb_try_make_writable(skb, thoff + hdrsize))
		return NF_DROP;

	flow_offload_refresh(flow_table, flow);

	nf_flow_encap_pop(skb, tuplehash);

	ip6h = ipv6_hdr(skb);
	nf_flow_nat_ipv6(flow, skb, dir, ip6h);

	ip6h->hop_limit--;
	skb->tstamp = 0;

	if (flow_table->flags & NF_FLOWTABLE_COUNTER)
		nf_ct_acct_update(flow->ct, tuplehash->tuple.dir, skb->len);

	if (unlikely(tuplehash->tuple.xmit_type == FLOW_OFFLOAD_XMIT_XFRM)) {
		rt = (struct rt6_info *)tuplehash->tuple.dst_cache;
		memset(skb->cb, 0, sizeof(struct inet6_skb_parm));
		IP6CB(skb)->iif = skb->dev->ifindex;
		IP6CB(skb)->flags = IP6SKB_FORWARDED;
		return nf_flow_xmit_xfrm(skb, state, &rt->dst);
	}

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
	}

	return ret;
}
EXPORT_SYMBOL_GPL(nf_flow_offload_ipv6_hook);
