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
#include <math.h>

#ifdef SUPPORT_802_11_A
#define SUPPORT_802_11A "IEEE 802.11a"
#else
#define SUPPORT_802_11A "no"
#endif

#define SUPPORT_802_11_BG "IEEE 802.11bg"

#define WIRELESS_CONFIG "/etc/config/wireless"

#define MAX_RATE 54e6
#define MIN_RATE (0.5*MAX_RATE)
#define MIN_THRES MIN_RATE/MAX_RATE
#define T_HOLD 10
#define INITIAL_HOLD 1
#define FILTER_CONSTANT ((float)T_HOLD/(T_HOLD+1))

#define CONFIG_FILE "/etc/chswi.conf"

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



float get_channel_load(int skfd,const char *ifname,unsigned int timeslot);

int
get_initial_load(int skfd,const char *ifname,int timeslot,channel_list *lst);

int switch_mode(int skfd,const char *ifname,int mode);

void if_up_down(int skfd,const char *vname, int value);

int check_proto_support(int skfd,const char *ifname,const char *proto);

int switch_channel(int skfd,const char *ifname, int channel);

int is_outdated(channel_list *lst);

void channel_selection(int skfd,const char *ifname,const char *master, const char *physical);

int switch_ap_channel(const char *physical_dev, int channel);

channel_load* find_oldest(channel_list *lst);

void find_less_congested(channel_list *lst,channel_load **less_cong,
		float * second_less);

int get_range_info(int		skfd, const char *	ifname,
		  iwrange *	range);

int read_config(char *ap_iface,char *m_iface, char *phy_dev);

static int channel_support(float freq,int supports_a);

static int
print_info(int skfd, char * ifname, char * args[], int count);

static int
get_info(int skfd, char * ifname, struct wireless_info * info);

static inline void display_info(struct wireless_info *	info, char * ifname)
{
  printf("%-8.16s  %s  \n\n", ifname, info->b.name);
}

inline void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	(*((float *)args))+=header->len;
}
#endif /* CHSWI_H_ */
