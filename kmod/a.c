#include <asm/system.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>

MODULE_DESCRIPTION("nm");
MODULE_AUTHOR("nm");
MODULE_LICENSE("GPL");
MODULE_VERSION("1.0");

static rx_handler_result_t pkt_receive(struct sk_buff **pskb)
{
	struct sk_buff *skb = *pskb;
	struct net_device *dev = skb->dev;
	kfree_skb(skb);
	return RX_HANDLER_PASS;
}

static int __init nminit(void) {
	char *dev = "eth0";
	netdev_rx_handler_register(dev, pkt_receive, 0);
}

static void __exit nmexit(void) { 
	char *dev = "eth0";
	netdev_rx_handler_unregister(dev);
}

module_init(nminit);
module_exit(nmexit);

