//////////////////////////////
//	subject: IPK 			//
//	project: packet sniffer //
//	name: Terezia Sochova	//
//	login: xsocho14			//
//	date: April 2020		//
//////////////////////////////

#include <ifaddrs.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <stdio.h>
#include <iostream>
#include <unistd.h> 
#include <getopt.h>
#include <string.h>

#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netdb.h>

using namespace std;

/*ipk-sniffer.cpp functions*/
void Packet_sniffer(bool pflag, bool tflag, bool uflag, bool nflag, int number, int port, string interface);
void my_callback(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);
bool process_tcp(char *time, char *src_ip, char *dst_ip, const u_char *packet);
bool process_udp(char *time, char *src_ip, char *dst_ip, const u_char *packet);
char* IPtoNAME(char *ip_addr);
void Data_output ( const u_char* data , int size);



/*ipk-parser.cpp functions*/

int main(int argc, char *argv[]);

void Active_intrefaces();


void Unwanted_argument();

void Mising_argument(int var);

void Unknown_option(int var);
 
void Multiple_usage(int var);
