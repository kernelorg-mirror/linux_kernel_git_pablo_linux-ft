// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/rhashtable.h>
#include <net/netfilter/nf_flow_table.h>
#include <net/netfilter/nf_tables.h>
#include <linux/if_vlan.h>

static unsigned int
nf_flow_offload_inet_hook(void *priv, struct sk_buff *skb,
			  const struct nf_hook_state *state)
{
	struct vlan_ethhdr *veth;
	__be16 proto;

	switch (skb->protocol) {
	case htons(ETH_P_8021Q):
		if (!pskb_may_pull(skb, skb_mac_offset(skb) + sizeof(*veth)))
			return NF_ACCEPT;

		veth = (struct vlan_ethhdr *)skb_mac_header(skb);
		proto = veth->h_vlan_encapsulated_proto;
		break;
	case htons(ETH_P_PPP_SES):
		if (!nf_flow_pppoe_proto(skb, &proto))
			return NF_ACCEPT;
		break;
	default:
		proto = skb->protocol;
		break;
	}

	switch (proto) {
	case htons(ETH_P_IP):
		return nf_flow_offload_ip_hook(priv, skb, state);
	case htons(ETH_P_IPV6):
		return nf_flow_offload_ipv6_hook(priv, skb, state);
	}

	return NF_ACCEPT;
}

static unsigned int
__nf_flow_offload_hook_list(void *priv, struct sk_buff *unused,
			    const struct nf_hook_state *state, u32 flags)
{
	struct list_head *skb_list = state->skb_list;
	struct sk_buff *skb, *next;
	struct vlan_ethhdr *veth;
	LIST_HEAD(skb_ipv4_list);
	LIST_HEAD(skb_ipv6_list);
	__be16 proto;

	list_for_each_entry_safe(skb, next, skb_list, list) {
		skb_reset_network_header(skb);
		if (!skb_transport_header_was_set(skb))
			skb_reset_transport_header(skb);
		skb_reset_mac_len(skb);

		switch (skb->protocol) {
		case htons(ETH_P_8021Q):
			veth = (struct vlan_ethhdr *)skb_mac_header(skb);
			proto = veth->h_vlan_encapsulated_proto;
			break;
		case htons(ETH_P_PPP_SES):
			nf_flow_pppoe_proto(skb, &proto);
			break;
		default:
			proto = skb->protocol;
			break;
		}

		switch (proto) {
		case htons(ETH_P_IP):
			list_move_tail(&skb->list, &skb_ipv4_list);
			break;
		case htons(ETH_P_IPV6):
			list_move_tail(&skb->list, &skb_ipv6_list);
			break;
		}
	}

	if (flags & (1 << NFPROTO_IPV4) && !list_empty(&skb_ipv4_list))
		__nf_flow_offload_ip_hook_list(priv, &skb_ipv4_list, state->in);

	list_splice_tail(&skb_ipv4_list, skb_list);
	list_splice_tail(&skb_ipv6_list, skb_list);

	if (!list_empty(skb_list))
		return NF_ACCEPT;

	return NF_STOLEN;
}

static unsigned int
nf_flow_offload_ip_hook_list(void *priv, struct sk_buff *unused,
			     const struct nf_hook_state *state)
{
	return __nf_flow_offload_hook_list(priv, unused, state,
					   1 << NFPROTO_IPV4);
}

static unsigned int
nf_flow_offload_ipv6_hook_list(void *priv, struct sk_buff *unused,
				 const struct nf_hook_state *state)
{
	return __nf_flow_offload_hook_list(priv, unused, state,
					   1 << NFPROTO_IPV6);
}

static unsigned int
nf_flow_offload_inet_hook_list(void *priv, struct sk_buff *unused,
			       const struct nf_hook_state *state)
{
	return __nf_flow_offload_hook_list(priv, unused, state,
					   (1 << NFPROTO_IPV4) | (1 << NFPROTO_IPV6));
}

static int nf_flow_rule_route_inet(struct net *net,
				   struct flow_offload *flow,
				   enum flow_offload_tuple_dir dir,
				   struct nf_flow_rule *flow_rule)
{
	const struct flow_offload_tuple *flow_tuple = &flow->tuplehash[dir].tuple;
	int err;

	switch (flow_tuple->l3proto) {
	case NFPROTO_IPV4:
		err = nf_flow_rule_route_ipv4(net, flow, dir, flow_rule);
		break;
	case NFPROTO_IPV6:
		err = nf_flow_rule_route_ipv6(net, flow, dir, flow_rule);
		break;
	default:
		err = -1;
		break;
	}

	return err;
}

static struct nf_flowtable_type flowtable_inet = {
	.family		= NFPROTO_INET,
	.init		= nf_flow_table_init,
	.setup		= nf_flow_table_offload_setup,
	.action		= nf_flow_rule_route_inet,
	.free		= nf_flow_table_free,
	.hook		= nf_flow_offload_inet_hook,
	.hook_list	= nf_flow_offload_inet_hook_list,
	.owner		= THIS_MODULE,
};

static struct nf_flowtable_type flowtable_ipv4 = {
	.family		= NFPROTO_IPV4,
	.init		= nf_flow_table_init,
	.setup		= nf_flow_table_offload_setup,
	.action		= nf_flow_rule_route_ipv4,
	.free		= nf_flow_table_free,
	.hook		= nf_flow_offload_ip_hook,
	.hook_list	= nf_flow_offload_ip_hook_list,
	.owner		= THIS_MODULE,
};

static struct nf_flowtable_type flowtable_ipv6 = {
	.family		= NFPROTO_IPV6,
	.init		= nf_flow_table_init,
	.setup		= nf_flow_table_offload_setup,
	.action		= nf_flow_rule_route_ipv6,
	.free		= nf_flow_table_free,
	.hook		= nf_flow_offload_ipv6_hook,
	.hook_list	= nf_flow_offload_ipv6_hook_list,
	.owner		= THIS_MODULE,
};

static int __init nf_flow_inet_module_init(void)
{
	nft_register_flowtable_type(&flowtable_ipv4);
	nft_register_flowtable_type(&flowtable_ipv6);
	nft_register_flowtable_type(&flowtable_inet);

	return 0;
}

static void __exit nf_flow_inet_module_exit(void)
{
	nft_unregister_flowtable_type(&flowtable_inet);
	nft_unregister_flowtable_type(&flowtable_ipv6);
	nft_unregister_flowtable_type(&flowtable_ipv4);
}

module_init(nf_flow_inet_module_init);
module_exit(nf_flow_inet_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Pablo Neira Ayuso <pablo@netfilter.org>");
MODULE_ALIAS_NF_FLOWTABLE(AF_INET);
MODULE_ALIAS_NF_FLOWTABLE(AF_INET6);
MODULE_ALIAS_NF_FLOWTABLE(1); /* NFPROTO_INET */
MODULE_DESCRIPTION("Netfilter flow table mixed IPv4/IPv6 module");
