//////////////////////////////
//	subject: IPK 			//
//	project: packet sniffer //
//	name: Terezia Sochova	//
//	login: xsocho14			//
//	date: April 2020		//
//////////////////////////////

#include "ipk-sniffer.hpp"


int tcp = 0, udp = 0;
int choose_case = 0, num = 0, i=0, j=0 , p=0;
bool choose_port = false;
pcap_t* descr;
// function converting ip address to domain name if possible
// if it is not possible it returns ip address
char* IPtoNAME(char *ip_addr){
    struct in_addr ip_name;
    struct hostent *hp;
    //inet_aton from ipv4 to binary form
    if (inet_aton(ip_addr, &ip_name) != 0){
        if ((hp = gethostbyaddr((const void *)&ip_name,sizeof ip_name, AF_INET)) != NULL)
           	    	strcpy(ip_addr, hp->h_name);           	
    }

    return ip_addr;
}

// Prints data of a packet in hexadecimal and ASCII form
// and size of already printed data
// inspired by output in wireshark
void Data_output (const u_char *data , int size)
{

	int printed_bytes=0;
	char c;

	char line[17];
	// looping until the last data info
	for (int i = 0; i < size; ++i)
	{
		//if new line started print value of printed bytes
		if(printed_bytes == 0 || (printed_bytes) % 16 == 0){
			printf("0x%04x: ", printed_bytes);			
		}

		c = data[i];//load packet char by char

		//if 8 data char where printed make double space
		//for better reading of data
		if((i+1)%8 == 0 && (i+1)%16 != 0  && i!= 0){
			printf("%02x  ", (unsigned char)c);			
		}
		else{
			printf("%02x ", (unsigned char)c);
		}

		// checking if char is printable
		if(c >= 32 && c <= 128){
			line[i % 16] = c;
		}
		else{
			line[i % 16] = '.';	
		}

		// if one line 16 characters ver loaded or end of packet
		// print ASCII part of line
		if( ((i+1)%16 == 0 && i!= 0) ||  i == size - 1){

			//end byte 
			line[i%16 +1] = '\0';

			// adding spaces in case that line is not full
			for( j = strlen(line) ; j < 16; j++)
			{
				printf("   ");
			}
			if(strlen(line) < 8){
				printf(" ");	
			}

			printf(" %s\n", line);//
		}


		printed_bytes = printed_bytes + 1;
		
	}
	printf("\n");

}  

// function for processing tcp packets
// finding value of port needed for header ofoutput
bool process_tcp(int size, char *time, char *src_ip, char *dst_ip, const u_char *packet){

	struct ip *ip = (struct ip*)( packet  + sizeof(struct ether_header) );
     
    struct tcphdr *tcp =(struct tcphdr*)(packet + (ip->ip_hl*4) + sizeof(struct ether_header));

    if(choose_port == true){// port filter was set
    	if(p == ntohs(tcp->th_sport) || p == ntohs(tcp->th_dport)){
			printf("%s %s : %d > %s : %d\n\n",time, src_ip, ntohs(tcp->th_sport), dst_ip, ntohs(tcp->th_dport));
			Data_output(packet, size);
			return true;	    		
    	}
    	else{
    		return false;//packet using different port than in port filter 
    	}
    }
    else{// port filter was not set
		printf("%s %s : %d > %s : %d\n\n",time, src_ip, ntohs(tcp->source), dst_ip, ntohs(tcp->dest));
		Data_output(packet, size);
		return true;			    	
    }


}


// function for processing udp packets
bool process_udp(int size, char *time, char *src_ip, char *dst_ip, const u_char *packet){

	// struct is part of #include <netinet/ip.h>
	struct ip *ip = (struct ip*)( packet  + sizeof(struct ether_header) );
    
    //struct is part of #include <netinet/udp.h> 
    struct udphdr *udp =(struct udphdr*)(packet + (ip->ip_hl*4) + sizeof(struct ether_header));

    if(choose_port == true){//port filter set
  	
    	if(p == ntohs(udp->uh_sport) || p == ntohs(udp->uh_dport)){// checking destination and source port 
			printf("%s %s : %d > %s : %d\n\n",time, src_ip, ntohs(udp->uh_sport), dst_ip, ntohs(udp->uh_dport));
			Data_output(packet, size);
			return true;	    		
    	}
    	else{
    		return false;
    	}
    }
    else{
		printf("%s %s : %d > %s : %d\n\n",time, src_ip, ntohs(udp->source), dst_ip, ntohs(udp->dest));
		Data_output(packet, size);
		return true;			    	
    }    

}

//function for checking type of packet, finding dst ip and source
// sending info to procces udp or procces tcp funtions
void Packet_parsing(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{


	int size = header->len;
    char src_ip[256], dst_ip[256];
  	struct tm * time_tm;
  	char buffer [100], r_time[256];

	time_tm = gmtime(&header->ts.tv_sec); //from t_time to tm
	time_tm->tm_hour = 	time_tm->tm_hour + 2; //our time zone
	strftime (buffer,100,"%H:%M:%S",time_tm); //to string
	snprintf(r_time, sizeof r_time, "%s.%06ld", buffer, header->ts.tv_usec); //add microseconds	


    struct ip *ip_header = (struct ip*)(packet + sizeof(struct ether_header));


    strcpy(src_ip, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip, inet_ntoa(ip_header->ip_dst));

    strcpy(src_ip, IPtoNAME(src_ip));
    strcpy(dst_ip, IPtoNAME(dst_ip));


 	if(choose_case == 0){// printing both tcp and udp packets

		switch (ip_header->ip_p) //Choose the protocol
		{  
		    case 17: //UDP Protocol 17 value of UDP from IP header
		        if(tcp + udp < num){

		     		if(process_udp(size, r_time, src_ip, dst_ip, packet)){
		        		++udp;		     			
		     		}   	
		        } 
		        else{
		        	pcap_close(descr);
		    		exit(0);// n number of packets printed  	
		        }                   	
		        break;

		    case 6:  //TCP Protocol 6 value of TCP from IP header 
				if(tcp + udp < num){
		     		if(process_tcp(size, r_time, src_ip, dst_ip, packet)){
		        		++tcp;		     			
		     		} 		     		  	
		        }
		        else{
					pcap_close(descr);
		    		exit(0);// n number of packets printed   	
		        }

		        break;
		     
		    default: //Other protocols
		        break;

		}
	}	   
	if(choose_case == 2 && ip_header->ip_p == 17){// printing only udp 
		if(udp < num){
			if(process_udp(size, r_time, src_ip, dst_ip, packet)){
				++udp;
			} 
		}
		else{
			//pcap_close(descr);
			exit(0);// n number of packets printed
		}
	}
	if(choose_case == 1 && ip_header->ip_p == 6){//printing only tcp
		if(tcp < num){

			if (process_tcp(size, r_time, src_ip, dst_ip, packet)){
				++tcp;
			} 
		}
		else{
			pcap_close(descr);
			exit(0);// n number of packetes printed
		}
	}

}

// function for capturing packets and sending them to loop
// using pcap library
void Packet_sniffer( bool pflag, bool tflag, bool uflag, bool nflag, int number, int port, string interface){

	if( (tflag == true && uflag == true) || (tflag == false && uflag == false)){
		choose_case = 0; //filtering among tcp and udp packets
	}
	else if(tflag == true && uflag == false){
		choose_case = 1; //filtering among tcp packets
	}
	else{
		choose_case = 2; //filtering among udp packets
	}

	num = number;
	if(pflag == true){// checking if port switch set
		choose_port = true;
	}
	p = port;

    bool valid_dev = false;
    pcap_if_t *devices_array , *device;
    char errbuf[1024];
    const char *dev;

    //find all available devices
    int ret_val = pcap_findalldevs( &devices_array , errbuf); 
     
    // if pcap_findalldevs ended with error it returns -1 else 0
    if( ret_val == -1 )
    {
        printf("ERROR : %s", errbuf);
        exit(-1);
    }

    //looping over all available devices
    device = devices_array;
    //if there are no available devices
    while(device != NULL) {

        if(interface == device->name){
        	valid_dev = true;
        	dev = device->name;
        }
    	device = device->next;
    }


    // chceck if input interface was valid
    if(valid_dev == false){
    	fprintf(stderr, "ERROR: Invalid device.\n");
    	Active_intrefaces();
    }

    // function opens a device for capturing packets
    // dev that should be opened
    // errbuf string with error message
    // 0 packet buffer timeout  - delay
    // 0 not promiscuous mode
    // 65535 length of packet captured - sufficent to capture all data
    descr = pcap_open_live(dev, 65535, 1, 0, errbuf);

    // if failure
    if(descr == NULL){
    	printf("ERROR: %s\n",errbuf);
     	exit(-1);
    }

    // loop over packets on gives interface 
    // until infinity (-1), Filtering, 
    pcap_loop(descr, -1, Packet_parsing , NULL);
	   	
}


