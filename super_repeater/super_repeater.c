/* reference ldd3, snull.c */
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>

/* for in_device, in_ifaddr */
#include <linux/inetdevice.h>
#if 1 /* WenJuin add for struct iphdr  */
#include <net/ip.h>
#endif
#if 1
#include <linux/netfilter_bridge.h>	//for NF_BR_LOCAL_IN
#endif

#include "super_repeater.h"

MODULE_AUTHOR("Brook");
MODULE_DESCRIPTION("Kernel module for demo");
MODULE_LICENSE("GPL");

#define br_port_get(dev) ((struct nic_bridge_port *) dev->rx_handler_data)

#if 1 /* WenJuin add for super repeater net_device  */
static struct net_device *nic_dev_lb;
static struct net_device *dev_2g;
static struct net_device *dev_5g;
#endif

int policy = RE_5G_ONLY;
unsigned int lb_intf_index = 1;	//cur forwarding interface policy index, by default use 5g interface brcause it has more bandwidth.
char* lb_intf_name[RE_INTF_NUM]={
	RE_2G_INTF_NAME,
	RE_5G_INTF_NAME
};

//static struct net_device *nic_dev[2];
/* netif msg type, defined in netdevice.h
    NETIF_MSG_DRV           = 0x0001,
    NETIF_MSG_PROBE         = 0x0002,
    NETIF_MSG_LINK          = 0x0004,
    NETIF_MSG_TIMER         = 0x0008,
    NETIF_MSG_IFDOWN        = 0x0010,
    NETIF_MSG_IFUP          = 0x0020,
    NETIF_MSG_RX_ERR        = 0x0040,
    NETIF_MSG_TX_ERR        = 0x0080,
    NETIF_MSG_TX_QUEUED     = 0x0100,
    NETIF_MSG_INTR          = 0x0200,
    NETIF_MSG_TX_DONE       = 0x0400,
    NETIF_MSG_RX_STATUS     = 0x0800,
    NETIF_MSG_PKTDATA       = 0x1000,
    NETIF_MSG_HW            = 0x2000,
    NETIF_MSG_WOL           = 0x4000,
*/
#define DEF_MSG_ENABLE 0xffff
#if 0
static void dump(unsigned char *buf)
{
    unsigned char *p, sbuf[2*(sizeof(struct ethhdr) + sizeof(struct iphdr))];
    int i;
    p = sbuf;

    for(i = 0; i < sizeof(struct ethhdr); i++) {
        p += sprintf(p, "%02X ", buf[i]);
    }
    printk("eth %s\n", sbuf);

    p = sbuf;
    for(i = 0; i < sizeof(struct iphdr); i++) {
        p += sprintf(p, "%02X ", buf[sizeof(struct ethhdr) + i]);
    }
    printk("iph %s\n", sbuf);

    p = sbuf;
    for(i = 0; i < 4; i++) {
        p += sprintf(p, "%02X ", buf[sizeof(struct ethhdr) + sizeof(struct iphdr) + i]);
    }
    printk("payload %s\n", sbuf);
}
#endif

static int nic_open(struct net_device *netdev)
{
    struct nic_priv *priv = netdev_priv(netdev);
    netif_info(priv, ifup, netdev, "%s(#%d), priv:%p\n",
                __func__, __LINE__, priv);

    netif_start_queue(netdev);
    return 0;
}

static int nic_close(struct net_device *netdev)
{
    struct nic_priv *priv = netdev_priv(netdev);
    netif_info(priv, ifdown, netdev, "%s(#%d), priv:%p\n",
                __func__, __LINE__, priv);
    netif_stop_queue(netdev);
    return 0;
}

#if 1
void updateIntfByPolicy(void){
	
	switch(policy){
	case RE_2G_ONLY:
		// always deliver to RE 2.4g interface
		lb_intf_index = RE_2G_ONLY;
		break;
	case RE_5G_ONLY:
		// always deliver to RE 5g interface		
		lb_intf_index = RE_5G_ONLY;
		break;
	case INTF_EQUAL_PRIO:
		lb_intf_index = (lb_intf_index == RE_2G_ONLY)? RE_5G_ONLY:RE_2G_ONLY;	//switch each other
		break;
	case BANDWIDTH_POLICY:
		break;
	default:
		//default policy is RE_5G_ONLY
		lb_intf_index = RE_5G_ONLY;		
		break;
	}

	return;
}
#endif

static void lb_deliver(struct net_device *to, struct sk_buff *skb)
{
	skb->dev = to;
	dev_queue_xmit(skb);
}

static netdev_tx_t nic_start_xmit(struct sk_buff *skb,
                                  struct net_device *netdev)
{
	struct net_device *dev = NULL;
	//printk(KERN_INFO "Enter nic_start_xmit.\n");

	updateIntfByPolicy();
    dev = (lb_intf_index == RE_2G_ONLY)? dev_2g: dev_5g;

    if(dev) {	
		lb_deliver(dev ,skb);
        dev_put(dev);
        dev = NULL;
    }else{
    	printk(KERN_INFO "nic_start_xmit fail, Can not get %s net_device.\n", lb_intf_name[lb_intf_index]);
		return NETDEV_TX_LOCKED;
    }	

    return NETDEV_TX_OK;
}

static int nic_validate_addr(struct net_device *netdev)
{
    struct nic_priv *priv = netdev_priv(netdev);
    netif_info(priv, drv, netdev, "%s(#%d), priv:%p\n",
                __func__, __LINE__, priv);
    return eth_validate_addr(netdev);
}

static int nic_change_mtu(struct net_device *netdev, int new_mtu)
{
    struct nic_priv *priv = netdev_priv(netdev);
    netif_info(priv, drv, netdev, "%s(#%d), priv:%p\n",
                __func__, __LINE__, priv);
    return eth_change_mtu(netdev, new_mtu);
}

static int nic_set_mac_addr(struct net_device *netdev, void *addr)
{
    struct nic_priv *priv = netdev_priv(netdev);
    netif_info(priv, drv, netdev, "%s(#%d), priv:%p\n",
                __func__, __LINE__, priv);
    return eth_mac_addr(netdev, addr);
}

static const struct net_device_ops nic_netdev_ops = {
    /* Kernel calls ndo_open() and ndo_validate_addr()
     * when you bring up the NIC
     */
    .ndo_open               = nic_open,
    .ndo_validate_addr      = nic_validate_addr,

    /* when you shut down the NIC, kernel call the .ndo_stop() */
    .ndo_stop               = nic_close,

    /* Kernel calls ndo_start_xmit() when it wants to 
     *   transmit a packet. 
     */
    .ndo_start_xmit         = nic_start_xmit,

    /* ndo_change_mtu() is called, when you change MTU */
    .ndo_change_mtu         = nic_change_mtu,

    /* ndo_set_mac_address() is called,
     *   when you change the MAC addr
     */
    .ndo_set_mac_address    = nic_set_mac_addr,
};


#if 1 /* WenJuin add for can not find eth_hw_addr_random */
void br_dev_lb_setup(struct net_device *dev)
{

	/* for IPv6 Test, need assign the br0 mac addr from the flash not the random,
	   it wil make link local addr the same even if reboot,modify by liweijie,2014-08-19 */
	random_ether_addr(dev->dev_addr);

	ether_setup(dev);

    dev->netdev_ops = &nic_netdev_ops;
	//dev->destructor = br_dev_free;
	//SET_ETHTOOL_OPS(dev, &br_ethtool_ops);
	dev->tx_queue_len = 0;
	dev->priv_flags = IFF_EBRIDGE;

	dev->features = NETIF_F_SG | NETIF_F_FRAGLIST | NETIF_F_HIGHDMA |
			NETIF_F_GSO_MASK | NETIF_F_NO_CSUM | NETIF_F_LLTX |
			NETIF_F_NETNS_LOCAL | NETIF_F_GSO;
}
#endif

/* there are register device receive packet, modify input skb device and pass up packet to kernel */
struct sk_buff *lb_pass_frame_up(struct sk_buff *skb)
{
	const unsigned char *source = eth_hdr(skb)->h_source;
	
	//check the mac address, if match, drop it.
	if (!compare_ether_addr(nic_dev_lb->dev_addr, source) || !compare_ether_addr(dev_2g->dev_addr, source) || !compare_ether_addr(dev_5g->dev_addr, source)){
		kfree_skb(skb);
		return NULL;
	}
	
	skb->dev = nic_dev_lb;
	//printk(KERN_INFO "Enter lb_pass_frame_up from %s to %s\n", indev->name, skb->dev->name);

	netif_receive_skb(skb);	//pass skb to dev.c again
	return NULL;
}

static struct nic_bridge_port *new_nbp(struct nic_priv *priv,
				       struct net_device *dev)
{
	struct nic_bridge_port *p;

	p = kzalloc(sizeof(*p), GFP_KERNEL);
	if (p == NULL)
		return ERR_PTR(-ENOMEM);

	p->br_priv = priv;
	dev_hold(dev);
	p->dev = dev;

	return p;
}


/* netlink handler function */
static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    nlmsg_type msgtype;
	struct net_device *dev = NULL;
	struct nic_bridge_port *p;
	struct nic_priv *priv;
	bool flag = false;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    /* parser netlink socket data */
    nlh = (struct nlmsghdr *)skb->data; /* data content */
    pid = nlh->nlmsg_pid; /*pid of sending process */
    printk(KERN_INFO "Netlink received msg payload[PID=%d]:\"%d, %s\"\n", pid,
			((nl_msg *)nlmsg_data(nlh))->type, ((nl_msg *)nlmsg_data(nlh))->data);

    msgtype=((nl_msg *)nlmsg_data(nlh))->type;

    switch(msgtype)
    {
    case NLMSG_ADDIF:
		priv = netdev_priv(nic_dev_lb);

		rcu_read_lock();
		list_for_each_entry_rcu(p, &priv->port_list, list) {
			if(strncmp(p->dev->name, ((nl_msg *)nlmsg_data(nlh))->data, strlen(((nl_msg *)nlmsg_data(nlh))->data)) == 0){
				printk(KERN_INFO "%s is already in %s.\n", ((nl_msg *)nlmsg_data(nlh))->data, nic_dev_lb->name);
				flag = true;
			}
		}
		rcu_read_unlock();
		
		rtnl_lock();
        dev = dev_get_by_name(&init_net, ((nl_msg *)nlmsg_data(nlh))->data);
        if(dev && flag == false) {
			priv = netdev_priv(nic_dev_lb);
			p = new_nbp(priv, dev);
			netdev_rx_handler_register(dev, lb_pass_frame_up, p);

			list_add_rcu(&p->list, &priv->port_list);
			
            dev_put(dev);
            dev = NULL;
        }else{
        	printk(KERN_INFO "register fail, Can not get %s net_device.\n", ((nl_msg *)nlmsg_data(nlh))->data);
        }
		rtnl_unlock();
		break;
	case NLMSG_DELIF:
		priv = netdev_priv(nic_dev_lb);

		rcu_read_lock();
		list_for_each_entry_rcu(p, &priv->port_list, list) {
			if(strncmp(p->dev->name, ((nl_msg *)nlmsg_data(nlh))->data, strlen(((nl_msg *)nlmsg_data(nlh))->data)) == 0){
				printk(KERN_INFO "%s is already in %s.\n", ((nl_msg *)nlmsg_data(nlh))->data, nic_dev_lb->name);
				flag = true;
			}
		}
		rcu_read_unlock();
		
		rtnl_lock();
        dev = dev_get_by_name(&init_net, ((nl_msg *)nlmsg_data(nlh))->data);
        if(dev && flag == true) {
			priv = netdev_priv(nic_dev_lb);
			p = br_port_get(dev);
			if (p->br_priv != priv)
				return;
			
			list_del_rcu(&p->list);
			kfree(p);
			
			netdev_rx_handler_unregister(dev);
			
            dev_put(dev);
            dev = NULL;
        }else{
        	printk(KERN_INFO "Unregister fail, Can not get %s net_device.\n", ((nl_msg *)nlmsg_data(nlh))->data);
        }
		rtnl_unlock();
		break;
	case NLMSG_SET_LB_POLOCY:
		policy = ((nl_msg *)nlmsg_data(nlh))->index;
		printk(KERN_INFO "Set Super Repeater Policy to %d.\n", policy);		
		break;
    default:
		printk(KERN_INFO "%s, Unknown netlink msg type[%d].\n", __FUNCTION__, msgtype);
		break;
	}

}

static struct net_device* nic_alloc_netdev(void)
{
	//struct nic_priv *priv;
    struct net_device *netdev;

	netdev = alloc_netdev(sizeof(struct nic_priv), "br-lb%d",
			br_dev_lb_setup);

    if (!netdev) {
        pr_err("%s(#%d): alloc dev failed",
               __func__, __LINE__);
        return NULL;
    }

    return netdev;
}

static int __init brook_init(void)
{
    int ret;
    struct nic_priv *priv;

    nic_dev_lb = nic_alloc_netdev();
    if (!nic_dev_lb) {
        pr_err("%s(#%d): alloc netdev[0] failed", __func__, __LINE__);
        return -ENOMEM;
    }

	priv = netdev_priv(nic_dev_lb);
	priv->dev = nic_dev_lb;
	INIT_LIST_HEAD(&priv->port_list);

    ret = register_netdev(nic_dev_lb);
    if (ret) {
        pr_err("%s(#%d): reg net driver failed. ret:%d",
               __func__, __LINE__, ret);
        return ret;
    }

	/* add the netlink for runtime control */
	nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, nl_recv_msg, NULL, THIS_MODULE);

	/* init repeater interface */
	dev_2g = dev_get_by_name(&init_net, RE_2G_INTF_NAME);
	if(!dev_2g) {	
		printk(KERN_INFO "2.4g net_dev init fail, Can not get %s net_device.\n", RE_2G_INTF_NAME);
	}

	dev_5g = dev_get_by_name(&init_net, RE_5G_INTF_NAME);
	if(!dev_5g) {	
		printk(KERN_INFO "5g net_dev init fail, Can not get %s net_device.\n", RE_5G_INTF_NAME);
	}
	
    return 0;
}
module_init(brook_init);

static void __exit brook_exit(void)
{
    pr_info("%s(#%d): remove module", __func__, __LINE__);
	//release netdev
    unregister_netdev(nic_dev_lb);
    free_netdev(nic_dev_lb);

	if(dev_2g) {	
		printk(KERN_INFO "2.4g net_dev init fail, Can not get %s net_device.\n", RE_2G_INTF_NAME);
	    dev_put(dev_2g);
	    dev_2g = NULL;		
	}

	if(dev_5g) {	
		printk(KERN_INFO "5g net_dev init fail, Can not get %s net_device.\n", RE_5G_INTF_NAME);
	    dev_put(dev_5g);
	    dev_5g = NULL;
	}
}
module_exit(brook_exit);

