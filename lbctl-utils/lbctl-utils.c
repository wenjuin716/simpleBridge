#include <sys/socket.h>
#include <linux/netlink.h>
#include "nlmsg.h"	// netlink message detail define

#define NETLINK_USER 31
#define MAX_PAYLOAD 1024 /* maximum payload size*/

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

void usage(void){
	printf("==========================\n");
	printf("lbctl 0 <device name>\n");
	printf("\tadd device into super repeater bridge\n");
	printf("lbctl 1 <device name>\n");
	printf("\tdelete device into super repeater bridge\n");
	printf("lbctl 2 <policy>\n");
	printf("\t0:RE_2G_ONLY\n");
	printf("\t1:RE_5G_ONLY\n");	
	printf("\t2:INTF_EQUAL_PRIO\n");		
	printf("==========================\n");
}

void main(int argc, char** argv)
{
	nl_msg nlmsg;

	if(argc == 1){
		usage();
		return;
	}

	switch(atoi(argv[1])){
	case NLMSG_ADDIF:
		if(argc == 3){
			nlmsg.type = NLMSG_ADDIF;
			strcpy(&(nlmsg.data), argv[2]);
		}
		break;
	case NLMSG_DELIF:
		if(argc == 3){
			nlmsg.type = NLMSG_DELIF;
			strcpy(&(nlmsg.data), argv[2]);
		}
	break;	
	case NLMSG_SET_LB_POLOCY:
		if(argc == 3){
			nlmsg.type = atoi(argv[1]);
			nlmsg.index = atoi(argv[2]);
			//printf("send msg NLMSG_SET_LB_POLOCY, policy=%d\n", nlmsg.index);
		}
		break;
	default:
		printf("No Msg to send\n");
		usage();
		return;
	}

	sock_fd=socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);  
	if(sock_fd<0)  
		return -1;  

	memset(&src_addr, 0, sizeof(src_addr));  
	src_addr.nl_family = AF_NETLINK;  
	src_addr.nl_pid = getpid();  /* self pid */  
	/* interested in group 1<<0 */  
	bind(sock_fd, (struct sockaddr*)&src_addr, sizeof(src_addr));  


	/* Send Netlink msg to Kernel */
	memset(&dest_addr, 0, sizeof(dest_addr));
	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;   /* For Linux Kernel */
	dest_addr.nl_groups = 0; /* unicast */

	nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
	memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
	nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
	//nlh->nlmsg_type = NLMSG_DONE; 	/* NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE */
	/* Request an ack from kernel by setting NLM_F_ACK. */
	nlh->nlmsg_flags |= NLM_F_ACK;
	//nlh->nlmsg_seq = 0;
	nlh->nlmsg_pid = getpid();

	memcpy(NLMSG_DATA(nlh), &nlmsg, sizeof(nl_msg));

	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	//printf("Sending message to kernel\n");
	sendmsg(sock_fd,&msg,0);

#if 0
	/* Read message from kernel */
        printf("Waiting for message from kernel\n");
	recvmsg(sock_fd, &msg, 0);
	printf(" Received message payload: \"%s\"\n", NLMSG_DATA(nlh));
#endif
	close(sock_fd);
}
