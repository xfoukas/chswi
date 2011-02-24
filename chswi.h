/*
 * chswi.h
 *
 *  Created on: Nov 24, 2010
 *      Author: Xenofon Foukas,
 *      		p3070185@dias.aueb.gr
 */

#ifndef CHSWI_H_
#define CHSWI_H_

/************************ INCLUDES **************************/

#include <stdio.h>
#include <iwlib.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <signal.h>
#include <time.h>
#include <math.h>

/********************** CONSTANTS & MACROS ******************/

/*For support of protocol 802.11a*/
#ifdef SUPPORT_802_11_A
#define SUPPORT_802_11A "IEEE 802.11a"
#else
#define SUPPORT_802_11A "no"
#endif

/*Supported protocols*/
#define SUPPORT_802_11_BG "IEEE 802.11bg"

/*Location of wireless configuration file*/
#define WIRELESS_CONFIG "/etc/config/wireless"
/*Location of application config file*/
#define CONFIG_FILE "/etc/chswi.conf"

/*Useful Constants*/
#define MAX_RATE 54e6
#define T_HOLD 10
#define INITIAL_HOLD 1

/*Maximum accepted rate before changing channel*/
#define MIN_RATE (0.4*MAX_RATE)
#define MIN_THRES (MIN_RATE/MAX_RATE)
#define FILTER_CONSTANT ((float)(T_HOLD-1)/T_HOLD)

/************************** DEBUG ****************************/

#define DEBUG 1

/************************** TYPES ****************************/

/* Structure for storing information about a channel that
 * has been scanned. This will be used as a node for a linked
 * list of scanned channels */
typedef struct chanload
{
	int has_channel;
	int channel;			/* Channel number */
	float freq;				/* Channel frequency */
	int has_load;
	float load;				/* Channel load */
	time_t measure_time;	/* Time that the measurement occured */
	int has_next;
	struct chanload * next;	/* Next channel that was scanned */
} channel_load;

/* Linked List containing all the channels that were scanned */
typedef struct chlist
{
	channel_load * channels;			/* List of channels */
	unsigned short num_of_channels; /* Number of channels in the list */
}channel_list;


/*************************** PROTOTYPES *********************************/

/* -------------------- Channel Selection Subroutine ------------------- */
void channel_selection(int skfd, const char * ifname,
			const char * master, const char * physical);


/* --------------------- Load Measurement Subroutines ------------------ */
float get_channel_load(int skfd, const char * ifname,
					unsigned int timeslot);

int
get_initial_load(int skfd, const char * ifname, int timeslot,
					channel_list * lst);


/* ----------- Wireless Interface Manipulation Subroutines -------------- */
int switch_mode(int skfd, const char * ifname, int mode);

int switch_channel(int skfd, const char * ifname, int channel);

void if_up_down(int skfd, const char * vname, int value);

int switch_ap_channel(const char * physical_dev, int channel);


/* -------------------- Auxiliary Subroutines -------------------------- */
int check_proto_support(int skfd, const char * ifname, const char * proto);

int is_outdated(channel_list * lst);

channel_load* find_oldest(channel_list * lst);

void find_less_congested(channel_list * lst, channel_load ** less_cong,
			float * second_less);

static int channel_support(float freq, int supports_a);


/* -------------- Information Gathering Subroutines --------------------- */
int read_config(char * ap_iface, char * m_iface, char * phy_dev);

int get_range_info(int skfd, const char * ifname,
		  	  iwrange *	range);

static int
print_info(int skfd, char * ifname, char * args[], int count);

static int
get_info(int skfd, char * ifname, struct wireless_info * info);


/*************************** INLINE FUNCTIONS ****************************/

static inline void display_info(struct wireless_info *	info, char * ifname)
{
  fprintf(stdout,"%-8.16s  %s  \n\n", ifname, info->b.name);
}

inline void
got_packet(u_char * args, const struct pcap_pkthdr * header, const u_char * packet){
	(*((float *)args))+=header->len;
}
#endif /* CHSWI_H_ */
