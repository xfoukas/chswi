/*
 * chswi.h
 *
 *  Created on: Nov 24, 2010
 *      Author: Xenofon Foukas,
 *      		p3070185@dias.aueb.gr
 */

#ifndef CHSWI_H_
#define CHSWI_H_

#include <stdio.h>
#include <iwlib.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <signal.h>
#include <time.h>

#ifdef SUPPORT_802_11_A
#define SUPPORT_802_11A "IEEE 802.11a"
#else
#define SUPPORT_802_11A "no"
#endif

#define SUPPORT_802_11_BG "IEEE 802.11bg"

#define MAX_RATE 54e6
#define MIN_RATE (0.2*MAX_RATE)
#define MIN_THRES MIN_RATE/MAX_RATE
#define T_HOLD 10
#define INITIAL_HOLD 1
#define FILTER_CONSTANT ((float)T_HOLD/(T_HOLD+1))

typedef struct apinf
{
	int has_ap;
	wireless_config ap_config;
	iwqual ap_quality;
	struct apinf *next;
} ap_info;

typedef struct scanresult
{
	ap_info *ap_lists;
	int num_of_channels;    /*Number of channels checked*/
} scan_result;

typedef struct chanload
{
	int has_channel;
	int has_load;
	int has_next;
	int channel;
	float freq;
	float load;
	time_t measure_time;
	struct chanload *next;
} channel_load;

typedef struct chlist
{
	channel_load *channels;
	unsigned short num_of_channels;
}channel_list;

int sockets_open(void);

int ap_scan(int skfd,char *ifname,scan_result *lst);

float get_channel_load(int skfd,const char *ifname,unsigned int timeslot);

int
get_initial_load(int skfd,const char *ifname,int timeslot,channel_list *lst);

int switch_mode(int skfd,const char *ifname,int mode);

void if_up_down(int skfd,const char *vname, int value);

int check_proto_support(int skfd,const char *ifname,const char *proto);

int switch_channel(int skfd,const char *ifname, int channel);

int is_outdated(channel_list *lst);

void channel_selection(int skfd,const char *ifname);

channel_load* find_oldest(channel_list *lst);

void find_less_congested(channel_list *lst,channel_load **less_cong,
		channel_load **second_less);

static inline void sockets_close(int skfd)
{
	close(skfd);
}

static inline int channel_support(float freq,int supports_a){
	int divisor;
	float nfreq;
	if(freq>=GIGA)
		divisor=GIGA;
	else
		divisor=-1;
	nfreq=freq/divisor;
	if(nfreq>=2.4&&nfreq<2.5)
		return (1);
	else if(supports_a==1&&nfreq>5&&nfreq<5.7)
		return (1);
	return (-1);
}

inline void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	(*((float *)args))+=header->len;
}
#endif /* CHSWI_H_ */
