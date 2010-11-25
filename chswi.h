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

typedef struct apinf
{
	int has_ap;
	wireless_config ap_config;
	iwqual ap_quality;
	struct apinf *next;
} ap_info;


typedef struct chlist
{
	ap_info *list_by_channel;			/*List of the first channel*/
	unsigned short num_of_channels;    /*Number of channels checked*/
} channel_list;

int ap_scan(int skfd,char *ifname,channel_list *lst);

int get_channel_load(const char *ifname,unsigned int timeslot);

int switch_mode(int skfd,char *ifname,int mode);

void if_up_down(int skfd,const char *vname, int value);

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
