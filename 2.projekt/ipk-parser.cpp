//////////////////////////////
//	subject: IPK 			//
//	project: packet sniffer //
//	name: Terezia Sochova	//
//	login: xsocho14			//
//	date: April 2020		//
//////////////////////////////

#include "ipk-sniffer.hpp"

// function chech and print all active network interfaces
void Active_intrefaces(){

	printf("ALL ACTIVE INTERFACES:\n");
    
	//find all available devices

    pcap_if_t *devices_array , *device;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret_val = pcap_findalldevs( &devices_array , errbuf); 
     
    // if pcap_findalldevs ended with error it returns -1 else 0
    if( ret_val == -1 )
    {
        printf("ERROR : %s", errbuf);
        exit(-1);
    }

    //looping over all available devices
    device = devices_array;
    int n = 1;
    //print all available devices
    while(device != NULL) {
    	if(((device->flags & PCAP_IF_UP) != 0) && ((device->flags & PCAP_IF_RUNNING) != 0)){
    		printf("%d: %s\n", n, device->name);
    		n++;
    	}	
    	device = device->next;
    }

    exit(-1);

}

//ERROR MESSAGES (exit code == -1)


// funtion for printing error message if there were arguments with option --udp or --tcp
void Unwanted_argument(){

	fprintf(stderr,	"***************************** ERROR MESSAGE *****************************\n\n"
		  	"ERROR: -u|--udp or -t|--tcp switch can not have argument.\n\n");
	exit(-1);

}

// function for printing error message in case that argument is missing (-p, -i)
void Mising_argument(int var){
    fprintf(stderr,	"***************************** ERROR MESSAGE *****************************\n\n"
    		"ERROR: Missing argument for -%c switch.\n\n", var);

    if(var == 'i'){
    	Active_intrefaces();
    }
    else{
    	exit(-1);
    }
}

// function for printing error message in case that option is uknown or
// short option contains two dashes (--) or long option contains one dash (-). 
void Unknown_option(int var){

    fprintf(stderr,	"***************************** ERROR MESSAGE *****************************\n\n"
    		"ERROR: -%c is unknown option.\n\n", var);
    exit(-1);
}
 
// function for printing error message in case of multiple definition of one option. 
void Multiple_usage(int var){
    fprintf(stderr,	"***************************** ERROR MESSAGE *****************************\n\n"
    		"ERROR: Option -%c can not be used in command more than one.\n\n", var);
    exit(-1);
}

int main(int argc, char *argv[]) {

	int opt;
	int opt_index, port = 0;
	int number = 1;// implicit value of -n swith
	bool iflag=false, pflag=false, tflag=false, uflag=false, nflag = false;
	string interface;	

	// long options --tcp | --udp
	//struct contains - name, integer if has argument, flag, value
	static struct option long_opt[]={
		{"tcp", no_argument, 0, 't'},
		{"udp", no_argument, 0, 'u'}
	}; 

	// looping until the last argument
	// : after letter means obligatory argument after switch 
	while((opt = getopt_long(argc, argv, "-:i:n:p:ut", long_opt, &opt_index )) != -1){
		switch(opt){
			// interface -i value
			case 'i':
				if(iflag == false){
					interface = optarg;
					iflag = true;
					if (strncmp(optarg, "-", 1) == 0){
						Mising_argument(opt);
					}
				}
				else{
					Multiple_usage(opt);
				}

				break;

			case 'p':
				//port -p number
				if(pflag == false){

					if (strncmp(optarg, "-", 1) == 0){
						Mising_argument(opt);
					}
					port = stoi(optarg);// string to integer
					if(port < 0 || port > 65535 ){
						fprintf(stderr,"***************************** ERROR MESSAGE *****************************\n\n"
    					"ERROR: Range of port number is between 0 and 65535.\n\n");
    					exit(-1);
					}
					pflag = true;					
				}
				else{
					Multiple_usage(opt);
				}

				break;

			case 't':
				//tcp packet -t |--tcp 
				if(tflag == false ){
					// optarg is NULL
					tflag = true;
				}
				else{
					Multiple_usage(opt);
				}

				break;

			case 'u':
				// udp packet -u | --udp
				if(uflag == false ){
					uflag = true;
				}
				else{
					Multiple_usage(opt);
				}

				break;

			case 'n':
				// case if -n has an argument
				// number -n [number]
				if(nflag == false){

					if (strncmp(optarg, "-", 1) == 0){
						Mising_argument(opt);
					}
					number = stoi(optarg);// string to integer
					nflag = true;
					if(number < 1){
						fprintf(stderr, "***************************** ERROR MESSAGE *****************************\n\n"
    					"ERROR: Argumrnt of option -n must be a positive whole number.\n\n");
    					exit(-1);
					}
				}
				else{
					Multiple_usage(opt);
				}
				break;

			case '?':
				// case if strange character
				Unknown_option(optopt);
				break;

        	case ':':
        		// missing argument
        		Mising_argument(optopt);	
          		break;

			default :	
				Unwanted_argument();

		}

	}
	// checking if -i switch was set in command line
	if(iflag == false){
		printf("-i switch  is required. Possible arguments are listed below:\n");
		Active_intrefaces();
	}

	// calling function for sniffing packets
	Packet_sniffer(pflag, tflag, uflag, nflag, number, port, interface);	

    return 0;
}


