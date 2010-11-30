/*
 * chswi.c
 *
 *  Created on: Nov 24, 2010
 *      Author: Xenofon Foukas,
 *      		p3070185@dias.aueb.gr
 */

#include <err.h>
#include "chswi.h"

const char * const operation_mode[] = { "Auto",
					"Ad-Hoc",
					"Managed",
					"Master",
					"Repeater",
					"Secondary",
					"Monitor",
					"Unknown/bug" };

pcap_t *handle;

void terminate_monitor(int signum)
{
   pcap_breakloop(handle);
   pcap_close(handle);
}


int get_initial_load(int skfd,const char *ifname,int timeslot,channel_list *lst)
{
	int supports_a=0;
	int supports_bg=0;
	int i;
	channel_load *prev;
	struct iw_range range;

	if(check_proto_support(skfd,ifname,SUPPORT_802_11_BG)!=1) {
		fprintf(stderr,"Protocol %s is not supported",SUPPORT_802_11_BG);
		return (-1);
	} else
		supports_bg=1;

	if(check_proto_support(skfd,ifname,SUPPORT_802_11A)==1)
		supports_a=1;

	/*Find available channels*/
	if(iw_get_range_info(skfd,ifname,&range)<0) {
		 fprintf(stderr, "%-8.16s  no frequency information.\n\n",
				      ifname);
		 return (-1);
	}
	else
	lst->num_of_channels=0;
	lst->channels=malloc(range.num_channels*sizeof(channel_load));
	memset(lst->channels,0,range.num_channels*sizeof(channel_load));


	for(i=0;i<range.num_channels;i++){
		if(channel_support(iw_freq2float(&(range.freq[i])),supports_a)==1){
			lst->channels[i].has_channel=1;
			lst->channels[i].channel=range.freq[i].i;
			lst->channels[i].freq=iw_freq2float(&(range.freq[i]));
			lst->num_of_channels++;
			lst->channels[i].has_next=0;
			lst->channels[i].next=NULL;
			if(lst->num_of_channels>1){
				prev->has_next=1;
				prev->next=&(lst->channels[i]);
			}
			prev=&(lst->channels[i]);
		}
	}

	lst->channels=realloc(lst->channels,
			(lst->num_of_channels)*sizeof(channel_load));

	for(i=0;i<lst->num_of_channels;i++){
		if(lst->channels[i].has_channel) {
			if(switch_channel(skfd,ifname,lst->channels[i].channel)==-1){
				return (-1);
			}
			lst->channels[i].has_load=1;
			lst->channels[i].load=get_channel_load(skfd,ifname,timeslot);
			lst->channels[i].measure_time=time(NULL);
		}
	}
	return (1);
}

int switch_channel(int skfd,const char *ifname,int channel){
	struct iwreq wrq;
	int res;
	wrq.u.freq.m = (double) channel;
	wrq.u.freq.e = (double) 0;

	if(iw_set_ext(skfd, ifname, SIOCSIWFREQ, &wrq) < 0) {
		fprintf(stderr, "SIOCSIWFREQ: %s\n", strerror(errno));
		res=-1;
	}else
		res=1;
	return res;
}

int check_proto_support(int skfd,const char *ifname,const char *proto)
{
	struct iwreq wrq;
	char name[IFNAMSIZ+1];
	if(iw_get_ext(skfd, ifname, SIOCGIWNAME, &wrq) < 0)
		/*If no wireless name : no wireless extensions*/
		return(-1);
	else {
		strncpy(name, wrq.u.name, IFNAMSIZ);
		name[IFNAMSIZ] = '\0';
	}
	return iw_protocol_compare(name,proto);
}

float get_channel_load(int skfd,const char *ifname,unsigned int timeslot)
{
	float load;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct iwreq wrq;

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
	load=(100*load)/(MAX_RATE*timeslot);
	return load;
}

int switch_mode(int skfd,const char *ifname,int mode)
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

int is_outdated(channel_list *lst)
{
	int i;
	time_t now;
	now=time(NULL);
	for(i=0;i<lst->num_of_channels;i++){
		if(lst->channels[i].has_load==1){
			if((now-lst->channels[i].measure_time)>
				2*T_HOLD*lst->num_of_channels)
				return 1;
		}
	}
	return 0;
}

channel_load* find_oldest(channel_list *lst)
{
	channel_load *oldest;
	int i;
	oldest=lst->channels;
	for(i=0;i<lst->num_of_channels;i++){
		if(lst->channels[i].measure_time<oldest->measure_time)
			oldest=&(lst->channels[i]);
	}
	return oldest;
}

void find_less_congested(channel_list *lst,channel_load **less_cong,
		channel_load **second_less)
{
	int i;
	float second_less_load=1;
	*less_cong=lst->channels;
	*second_less=NULL;
	for(i=0;i<lst->num_of_channels;i++){
		if(lst->channels[i].load<(*less_cong)->load)
			*less_cong=&(lst->channels[i]);
		if(lst->channels[i].load<second_less_load
				&&lst->channels[i].load!=0){
			*second_less=&(lst->channels[i]);
			second_less_load=lst->channels[i].load;
		}
	}
}


void channel_selection(int skfd,const char *ifname)
{
	channel_list lst;
	channel_load ch,*less_cong,*second_less;
	channel_load *ch_old;
	float curr_thres,chan_load;
	int curr_channel,i;
	get_initial_load(skfd,ifname,INITIAL_HOLD,&lst);
	curr_thres=MIN_THRES;
	srand(time(NULL));
	curr_channel=(rand()%(lst.num_of_channels-1))+1;
	switch_channel(skfd,ifname,curr_channel);
	printf("Switched to channel %d\n",curr_channel);
	/*TODO must change interface of ap also*/
	while(1){
		chan_load=get_channel_load(skfd,ifname,T_HOLD);
		for(i=0;i<lst.num_of_channels;i++){
			if(lst.channels[i].has_channel==1){
				if(lst.channels[i].channel==curr_channel){
					ch=lst.channels[i];
					break;
				}
			}
		}
		ch.measure_time=time(NULL);
		ch.load=((1-FILTER_CONSTANT)*chan_load)+
				((FILTER_CONSTANT)*ch.load);
		printf("Channel load %f\n",ch.load);
		printf("Current load %f\n",curr_thres);
		if(ch.load>curr_thres){
			if(is_outdated(&lst)){
				ch_old=find_oldest(&lst);
				curr_channel=ch_old->channel;
				switch_channel(skfd,ifname,curr_channel);
				printf("Switched to channel old%d\n",curr_channel);
				/*TODO must change interface of ap also*/
				curr_thres=MIN_THRES;
			} else{
				find_less_congested(&lst,&less_cong,&second_less);
				printf("Less cong %d\n",less_cong->channel);
				curr_channel=less_cong->channel;
				switch_channel(skfd,ifname,curr_channel);
				printf("Switched to channel not old %d\n",curr_channel);
				/*TODO must change interface of ap also*/
				curr_thres=second_less->load;
			}
		}
	}
}

int main(int argc, char **argv)
{
	int skfd;
//	int i;
	if((skfd=iw_sockets_open())<0){
			perror("socket");
			return -1;
	}
	channel_selection(skfd,"wlan0");
	/*get_initial_load(skfd,"wlan1",1,&lst);
	for(i=0;i<lst.num_of_channels;i++){
		if(lst.channels[i].has_load)
			printf("%f, time: %u \n",lst.channels[i].load,lst.channels[i].measure_time);

	}*/
	switch_mode(skfd,"wlan0",2);
	iw_sockets_close(skfd);
	return (0);
}
