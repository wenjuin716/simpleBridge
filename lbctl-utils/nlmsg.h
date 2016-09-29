/* netlink Socket */
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
