
/*
 * snull.h -- definitions for the network module
 *
 * Copyright (C) 2001 Alessandro Rubini and Jonathan Corbet
 * Copyright (C) 2001 O'Reilly & Associates
 *
 * The source code in this file can be freely used, adapted,
 * and redistributed in source or binary form, so long as an
 * acknowledgment appears in derived source files.  The citation
 * should list that the code comes from the book "Linux Device
 * Drivers" by Alessandro Rubini and Jonathan Corbet, published
 * by O'Reilly & Associates.   No warranty is attached;
 * we cannot take responsibility for errors or fitness for use.
 */

/*
 * Macros to help debugging
 */

#undef PDEBUG             /* undef it, just in case */
#ifdef SNULL_DEBUG
#  ifdef __KERNEL__
     /* This one if debugging is on, and kernel space */
#    define PDEBUG(fmt, args...) printk( KERN_DEBUG "snull: " fmt, ## args)
#  else
     /* This one for user space */
#    define PDEBUG(fmt, args...) fprintf(stderr, fmt, ## args)
#  endif
#else
#  define PDEBUG(fmt, args...) /* not debugging: nothing */
#endif

#undef PDEBUGG
#define PDEBUGG(fmt, args...) /* nothing: it's a placeholder */


/* These are the flags in the statusword */
#define SNULL_RX_INTR 0x0001
#define SNULL_TX_INTR 0x0002

/* Default timeout period */
#define SNULL_TIMEOUT 5   /* In jiffies */

extern struct net_device *snull_devs[];

enum lb_policy{
	RE_2G_ONLY = 0,		//only used 2.4G interface
	RE_5G_ONLY,			//only used 5G interface
	INTF_EQUAL_PRIO,	//each interface equal priority
	BANDWIDTH_POLICY,	//Based on bandwidth allocation
};

#define MAX_ETH_FRAME_SIZE   1792
struct nic_priv {
    /* you can use array to queue more packet */
    u32           msg_enable;
	
	struct net_device		*dev;
	struct list_head		port_list;
};

struct nic_bridge_port {
	struct nic_priv		*br_priv;
	struct net_device		*dev;
	struct list_head		list;
};


#if 1	/* for netlink control */
struct sock *nl_sk = NULL;	/* netlink socket */
#define NETLINK_USER 31

#define MAX_MSGDATA_LEN 256
typedef enum nlmsg_type{
	NLMSG_ADDIF=0, // userspace -> kernel module
	NLMSG_DELIF,  // userspace -> kernel module
	NLMSG_SET_LB_POLOCY,	// userspace -> module
}nlmsg_type;

typedef struct nl_msg{
	nlmsg_type type;
	char data[MAX_MSGDATA_LEN];
	int index;
} nl_msg;
#endif

#define RE_INTF_NUM 	2	//total wireless interface
// those two interface is follow C55 naming rule, so you must change for other platform.
#define RE_2G_INTF_NAME "apcli0"
#define RE_5G_INTF_NAME "apclii0"


