/*
 * chswi.c
 *
 *  Created on: Nov 24, 2010
 *      Author: Xenofon Foukas,
 *      		p3070185@dias.aueb.gr
 */

#include "chswi.h"

const char * const operation_mode[] = { "Auto",
					"Ad-Hoc",
					"Managed",
					"Master",
					"Repeater",
					"Secondary",
					"Monitor",
					"Unknown/bug" };

/*int ap_scan(int skfd,char *ifname,channel_list *lst)
{
	struct iwreq wrq;
	struct iw_range range;
	ap_info *ap_array;
	wireless_scan_head cont;
	wireless_scan *scan;
	char name[IFNAMSIZ+1];

	memset((char*) lst,0,sizeof(channel_list));


	if(iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0)
	     If no wireless name : no wireless extensions
		return(-1);
	else {
		strncpy(name, wrq.u.name, IFNAMSIZ);
		name[IFNAMSIZ] = '\0';
	}

	Make sure interface is in managed mode
	 * or else change it so we can scan

	if(iw_get_ext(skfd, ifname, SIOCGIWMODE, &wrq) >= 0){
		if(wrq.u.mode!=2)
			if (switch_mode(skfd,ifname,2)<0)
				return (-1);
	}

	if(iw_scan(skfd,ifname,iw_get_kernel_we_version(),&cont)<0)
			return (-1);
	scan=cont.result;
	return (0);
}*/

int get_channel_load(const char *ifname,unsigned int timeslot)
{
	int load;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];

	/*Must be in monitor mode*/
	if(iw_get_ext(skfd, ifname, SIOCGIWMODE, &wrq) >= 0){
			if(wrq.u.mode!=6)
				if (switch_mode(skfd,ifname,6)<0)
					return (-1);
	}

	load=0;
	handle=pcap_open_live(ifname,BUFSIZ,1,1,NULL);
	if (handle==NULL){
		fprintf(stderr,"Couldn't open device %s: %s\n",ifname,errbuf);
		return(-1);
	}
	signal(SIGALRM, terminate_monitor);
	alarm(timeslot);
	pcap_loop(handle,-1,got_packet,(u_char *)&load);

	return load;
}

int switch_mode(int skfd,char *ifname,int mode)
{
	struct iwreq wrq;
	int res;
	if_up_down(skfd,ifname,-IFF_UP);
	wrq.u.mode=mode;
	res=iw_set_ext(skfd,ifname,SIOCSIWMODE,&wrq);
	if_up_down(skfd,ifname,IFF_UP);
	/*mode change failed but we first had to bring
		the interface back up*/
	if(res<0)
		return (-1);
	return (0);
}

void
if_up_down(int skfd,const char *vname, int value)
{
	struct ifreq ifreq;
	u_short flags;
	(void) strncpy(ifreq.ifr_name, vname, sizeof(ifreq.ifr_name));
 	if (ioctl(skfd, SIOCGIFFLAGS, &ifreq) == -1)
 		err(EXIT_FAILURE, "SIOCSIFFLAGS");
 	flags = ifreq.ifr_flags;

	if (value < 0) {
		value = -value;
		flags &= ~value;
	} else
		flags |= value;
	ifreq.ifr_flags = flags;
	if (ioctl(skfd, SIOCSIFFLAGS, &ifreq) == -1)
		err(EXIT_FAILURE, "SIOCSIFFLAGS");
}

int main(int argc, char **argv)
{
	/*int skfd;
	channel_list lst;
	if((skfd=iw_sockets_open())<0){
			perror("socket");
			return -1;
	}
	ap_scan(skfd,"wlan0",&lst);*/
	return (0);
}
