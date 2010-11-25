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
#include <err.h>
#include <time.h>

#define SUPPORTED_PROTO "IEEE 802.11bg"

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
	unsigned short num_of_channels;    /*Number of channels checked*/
} scan_result;

typedef struct chanload
{
	int channel;
	float load;
	time_t measure_time;
	struct chanload *next;
} channel_load;

typedef struct chlist
{
	channel_load *channels;
	unsigned short num_of_channels;
}channel_list;


int ap_scan(int skfd,char *ifname,channel_list *lst);

int get_channel_load(int skfd,const char *ifname,unsigned int timeslot);

int switch_mode(int skfd,char *ifname,int mode);

void if_up_down(int skfd,const char *vname, int value);

int check_proto_support(int skfd, const char *ifname);

inline void terminate_monitor(int signum)
{
//   pcap_breakloop(handle);
//   pcap_close(handle);
}

inline void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
	(*((int *)args))++;
}
#endif /* CHSWI_H_ */
