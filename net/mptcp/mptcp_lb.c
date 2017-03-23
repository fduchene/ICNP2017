#include <linux/module.h>

#include <net/mptcp.h>
#include <net/mptcp_v4.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/mptcp_v6.h>
#endif

#define PRIVATE_ADDR_ID 25

struct lb_priv {
	struct mptcp_cb *mpcb;
	union inet_addr private_addr;
	u8 private_addr_unacked; /* IPv4 Addresses we did announce but not acked yet */
};

static struct lb_priv *lb_get_priv(const struct mptcp_cb *mpcb)
{
	return (struct lb_priv *)&mpcb->mptcp_pm[0];
}
/*
static struct mptcp_lb_ns *lb_get_ns(const struct net *net)
{
	return (struct mptcp_lb_ns *)net->mptcp.path_managers[MPTCP_PM_LOADBALANCING];
}*/

static void lb_new_session(const struct sock *meta_sk)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct lb_priv *fmp = (struct lb_priv *)&mpcb->mptcp_pm[0];
	union inet_addr saddr, daddr;
	sa_family_t family;
	int if_idx;
	struct sock *sk;

	fmp->mpcb = mpcb;

	/* Init local variables necessary for the rest */
	if (meta_sk->sk_family == AF_INET || mptcp_v6_is_v4_mapped(meta_sk)) {
		saddr.ip = inet_sk(meta_sk)->inet_saddr;
		daddr.ip = inet_sk(meta_sk)->inet_daddr;
		if_idx = mpcb->master_sk->sk_bound_dev_if;
		family = AF_INET;
		mptcp_debug("%s: token %#x, new load balancing session on interface %d between src_addr:%pI4 dst_addr:%pI4\n",
			    __func__ , mpcb->mptcp_loc_token, if_idx, &saddr, &daddr);
#if IS_ENABLED(CONFIG_IPV6)
	} else {
		saddr.in6 = inet6_sk(meta_sk)->saddr;
		daddr.in6 = meta_sk->sk_v6_daddr;
		if_idx = mpcb->master_sk->sk_bound_dev_if;
		family = AF_INET6;
#endif
	}
	/* Put every subflow on backup mode */
	mptcp_for_each_sk(mpcb, sk) {
		struct tcp_sock *tp = tcp_sk(sk);
		tp->mptcp->rcv_low_prio = 1;
		tp->mptcp->low_prio = 1;
		tp->mptcp->send_mp_prio = 1;
	}
	fmp->private_addr = daddr;
	fmp->private_addr.ip |= 1 << 18;
	fmp->private_addr.in.s_addr |= 1 << 18;
	fmp->private_addr_unacked = 0;
	mptcp_debug("%s: generated IP ADDR :%pI4\n",  __func__ , &fmp->private_addr);
	mpcb->addr_signal = 1;
}

static void lb_create_address(struct sock *meta_sk)
{
	mptcp_debug("MPTCP established %#x\n", tcp_sk(meta_sk)->mpcb->mptcp_loc_token);
	/* Create a new IPv6 based on the token */
	/* New IPv6 : serverPrefix:sharedSecret:connToken */
	/*		64 bits   :  32 bits   : 32 bits */
	/* Create the addr, and then announce it in an ADD_ADDR */
	/* We don't need to store that IP after, because the validity */
	/* can be checked when the SYN+JOIN is received */
	
}

static void lb_addr_signal(struct sock *sk, unsigned *size,
				  struct tcp_out_options *opts,
				  struct sk_buff *skb)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct sock *meta_sk = mpcb->meta_sk;
	struct lb_priv *fmp = lb_get_priv(mpcb);
	bool meta_v4 = meta_sk->sk_family == AF_INET;

	mpcb->addr_signal = 0;

	rcu_read_lock();
	//mptcp_local = rcu_dereference(fm_ns->local);

	if (!meta_v4 && meta_sk->sk_ipv6only)
		goto skip_ipv4;

	/* IPv4 */
	if (((mpcb->mptcp_ver == MPTCP_VERSION_0 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR4_ALIGN) ||
	    (mpcb->mptcp_ver >= MPTCP_VERSION_1 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1))) {

		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->add_addr4.addr_id = PRIVATE_ADDR_ID;
		opts->add_addr4.addr = fmp->private_addr.in;
		opts->add_addr_v4 = 1;
		opts->add_addr_echo = 0;
		if (mpcb->mptcp_ver >= MPTCP_VERSION_1) {
			u8 mptcp_hash_mac[20];
			u8 no_key[8];

			*(u64 *)no_key = 0;
			mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
					(u8 *)no_key,
					(u32 *)mptcp_hash_mac, 2,
					1, (u8 *)PRIVATE_ADDR_ID,
					4, (u8 *)&fmp->private_addr.in.s_addr);
			opts->add_addr4.trunc_mac = *(u64 *)mptcp_hash_mac;
		}

		fmp->private_addr_unacked = 1;

		if (mpcb->mptcp_ver < MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
		if (mpcb->mptcp_ver >= MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1;

		goto skip_ipv6;
	}

	if (meta_v4)
		goto skip_ipv6;
skip_ipv4:
/*
	unannouncedv6 = (~fmp->announced_addrs_v6) & mptcp_local->loc6_bits;
	if (unannouncedv6 &&
	    ((mpcb->mptcp_ver == MPTCP_VERSION_0 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR6_ALIGN) ||
	    (mpcb->mptcp_ver >= MPTCP_VERSION_1 &&
	    MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR6_ALIGN_VER1))) {
		int ind = mptcp_find_free_index(~unannouncedv6);

		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->add_addr6.addr_id = mptcp_local->locaddr6[ind].loc6_id;
		opts->add_addr6.addr = mptcp_local->locaddr6[ind].addr;
		opts->add_addr_v6 = 1;
		if (mpcb->mptcp_ver >= MPTCP_VERSION_1) {
			u8 mptcp_hash_mac[20];
			u8 no_key[8];

			*(u64 *)no_key = 0;
			mptcp_hmac_sha1((u8 *)&mpcb->mptcp_loc_key,
					(u8 *)no_key,
					(u32 *)mptcp_hash_mac, 2,
					1, (u8 *)&mptcp_local->locaddr6[ind].loc6_id,
					16, (u8 *)&opts->add_addr6.addr.s6_addr);
			opts->add_addr6.trunc_mac = *(u64 *)mptcp_hash_mac;
		}

		if (skb) {
			fmp->announced_addrs_v6 |= (1 << ind);
			fmp->add_addr--;
		}
		if (mpcb->mptcp_ver < MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN;
		if (mpcb->mptcp_ver >= MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR6_ALIGN_VER1;
	}
*/
skip_ipv6:
	rcu_read_unlock();

	mpcb->addr_signal = 0;
	mpcb->addr_retrans_signal = fmp->private_addr_unacked;
}

static void lb_add_addr_ack_recv(struct sock *sk,
				const union inet_addr *addr,
				sa_family_t family, __be16 port, u8 id)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct lb_priv *fmp = lb_get_priv(mpcb);

	rcu_read_lock();

	if(fmp->private_addr_unacked && id == PRIVATE_ADDR_ID) {
		mptcp_debug("%s: YEAH ca match!\n", __func__);
		fmp->private_addr_unacked = 0;
	}

	mptcp_debug("%s: On sort de la fonction de vérification de l'echo avec %x comme valeur.\n", __func__, fmp->private_addr_unacked);
	mpcb->addr_retrans_signal = fmp->private_addr_unacked;
	rcu_read_unlock();
}

static void lb_rentrans_addr(struct sock *sk, unsigned *size,
				  struct tcp_out_options *opts,
				  struct sk_buff *skb)
{

	const struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tp->mpcb;
	struct lb_priv *fmp = lb_get_priv(mpcb);
	mpcb->addr_retrans_signal = 0;

	rcu_read_lock();


	if((mpcb->mptcp_ver == MPTCP_VERSION_0 &&
	      MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR4_ALIGN) ||
	      (mpcb->mptcp_ver >= MPTCP_VERSION_1 &&
	      MAX_TCP_OPTION_SPACE - *size >= MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1)) {
		mptcp_debug("%s: We didn't get an ACK for the ADDRID %d, retransmitting!\n", __func__, PRIVATE_ADDR_ID);
		opts->options |= OPTION_MPTCP;
		opts->mptcp_options |= OPTION_ADD_ADDR;
		opts->add_addr4.addr_id = PRIVATE_ADDR_ID;
		opts->add_addr4.addr = fmp->private_addr.in;
		opts->add_addr_v4 = 1;
		opts->add_addr_echo = 0;

		if (mpcb->mptcp_ver < MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN;
		if (mpcb->mptcp_ver >= MPTCP_VERSION_1)
			*size += MPTCP_SUB_LEN_ADD_ADDR4_ALIGN_VER1;
	}

	rcu_read_unlock();

	mpcb->addr_retrans_signal = fmp->private_addr_unacked;
}
static int lb_get_local_id(sa_family_t family, union inet_addr *addr,
				   struct net *net, bool *low_prio)
{
	return 0;
}

static struct mptcp_pm_ops lb __read_mostly = {
	.new_session = lb_new_session,
	.fully_established = lb_create_address,
	.addr_signal = lb_addr_signal,
	.get_local_id = lb_get_local_id,
	.retransmit_add_raddr = lb_rentrans_addr,
	.add_addr_ack_recv = lb_add_addr_ack_recv,
	.name = "loadbalancing",
	.owner = THIS_MODULE,
};

/* General initialization of MPTCP_PM */
static int __init lb_register(void)
{
	BUILD_BUG_ON(sizeof(struct lb_priv) > MPTCP_PM_SIZE);

	if (mptcp_register_path_manager(&lb))
		goto exit;

	return 0;

exit:
	return -1;
}

static void lb_unregister(void)
{
	mptcp_unregister_path_manager(&lb);
}

module_init(lb_register);
module_exit(lb_unregister);

MODULE_AUTHOR("Fabien Duchene");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Load-Balancing MPTCP");
MODULE_VERSION("0.90");
