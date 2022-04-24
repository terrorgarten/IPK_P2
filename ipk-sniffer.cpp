/**
 * @file sniffer.cpp
 * @author Matěj Konopík
 * @brief extended packet sniffer
 * @version 0.1
 * @date 2022-04-24
 * 
 * @copyright Copyright (c) 2022 Matěj Konopík, 2005 The Tcpdump Group(function )
 * 
 */
#include <cstddef>
#include <cstdio>
#include <exception>
#include <getopt.h>
#include <iostream> 	            //parse args
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <ostream>
#include <pcap.h>
#include <pcap/dlt.h>
#include <pcap/pcap.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <bitset> 	            //printing
#include <csignal>	            //trap ctrl+c
#include <netinet/in.h>
#include <pcap.h> 	            //catching packets, filters..
#include <arpa/inet.h>	        //misc, ntohs ntohl
#include <netinet/ether.h> 	    //arp, ether
#include <netinet/ip6.h> 	    //ipv6
#include <netinet/tcp.h>	    //tcp
#include <netinet/ip_icmp.h>	//ipv4, icmp
#include <sys/types.h>
#include <time.h>

//return codes
#define SUCCES  0
#define ERROR   1
//ethernet header size
#define SIZE_ETHERNET 14


//std namespace
using namespace std;


//global for correct access from cleanup()
pcap_t* dev_descriptor;


void print_interfaces();

void print_help(char* progname);

string load_filter(int udp, int tcp, int port, int arp, int icmp);

pcap_t* set_pcap_handle(string dev, string filter);

void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char *packet);

void clean_up(int s);

//function code from https://www.tcpdump.org/other/sniffex.c, see details at definition
void print_hex_ascii_line(const u_char *payload, int len, int offset);
//function code from https://www.tcpdump.org/other/sniffex.c, see details at definition 
void print_data(const u_char *payload, int len);



int main(int argc, char* argv[])
{
    //flag for tcp only mode
    int tcp_flag = 0;
    //flag for udp only mode
    int udp_flag = 0;
    //arp only mode
    int arp_flag = 0;
    //icmp only mode 
    int icmp_flag = 0;
    //interface specificator
    string interface = "";
    //port specificator, -1 when all
    int port = -1;
    //packet number specifier, 1 when default
    int packet_num = 1;

    //options
    static struct option long_opt[] = 
    {
        //setters
        {"interface", optional_argument, NULL, 'i'},
        {"num", required_argument, NULL, 'n'},
        //flags
        {"tcp", no_argument, &tcp_flag, 1},
        {"udp", no_argument, &udp_flag, 1},
        {"arp", no_argument, &arp_flag, 1},
        {"icmp", no_argument, &icmp_flag, 1},
        {0, 0, 0, 0}    
    };

    static char short_opt[] = "i::p:tun:h";
    //cmd line argument
    int cla;
    //index
    extern int optind;
    //cla loading loop
    while((cla = getopt_long(argc, argv, short_opt, long_opt, &optind)) != -1)
    {
        char* tmp_optarg = NULL;
        switch (cla) 
        {
            //flag set
            case 0:
                break;
            case 'i': //inspired by https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
                //check if the option argument exits
                if(!optarg && argv[optind] != NULL && '-' != argv[optind][0])
                {   
                    //if so, load it to the tmp var
                    tmp_optarg = argv[optind];                   
                }
                //check if load occured
                if(tmp_optarg){
                    //save the option argument int othe interface variable
                    interface.append(tmp_optarg);
                }
                // -i was specified alone, special case
                else 
                {   
                    // -i without param -> print interfaces
                    print_interfaces();
                }
                break;

            case 'p':
                //load port number into the specifier var
                port = stoi(optarg);
                //printf("port: %d", port);
                //cout << "Port: " << port << endl;
                break;

            case 't':
                //set TCP flag
                tcp_flag = 1;
                //cout << "TCP set" << endl;
                break;

            case 'u':
                //set UDP flag
                udp_flag = 1;
                //cout << "UDP set" << endl;
                break;
            
            case 'n':
                try
                {
                    packet_num = stoi(optarg);
                }
                catch(...)
                {
                    cerr << "Invalid parameter for -n. Use only positive numbers" << endl;
                    exit(ERROR);
                    //cerr << e.what() <<endl;
                }
                if(packet_num <= 0)
                {   
                    cerr << "Invalid parameter for -n. Use only positive numbers" << endl;
                    exit(ERROR);
                }
                break;
            case 'h':
                print_help(argv[0]);
                break;
            case '?':
            default:
                cout << "Uknown option. use -h for help.";
                break;
        }   
    }
    //debug print flags
    //cout << udp_flag << icmp_flag << tcp_flag << arp_flag << interface <<endl;

    
    
    //check if iface was set correctly 
    //TODO dead code?
    if(interface.empty())
    {
        cerr << "ERROR: No interface [-i|--interface] was specified. Use -h for help" << endl;
    }

    //loads a filter string depending on flags
    string filter = load_filter(udp_flag, tcp_flag, port, arp_flag, icmp_flag);
    cout << "FILTER: " << filter <<endl;
    
    //trap sigint for correct freeing of memmory
    signal(SIGINT, clean_up);

    //sets up the device descriptor
    dev_descriptor = set_pcap_handle(interface, filter);


    int datalink_type;
    if((datalink_type = pcap_datalink(dev_descriptor) < 0))
    {
        cerr << "ERROR: Could not determine datalink layer type. (pcap_datalink)";
        exit(ERROR);
    }

    //check for the type of datalink and accept only ethernet
    if(datalink_type != DLT_EN10MB)
    {
        cerr << "WARNING: Invalid datalink type - currently only Ethernet (EN10MB == 1) is supported. Current is  " << datalink_type << ". Run continues but results may be corrupted" << endl;
        //exit(ERROR);
    }

    //runs main loop for catching packets
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_loop(dev_descriptor, packet_num, handle_packet, NULL) < 0)
    {
        cerr << "Error during packet read loop, pcap: " << errbuf << endl;
        exit(ERROR);
    };



    pcap_close(dev_descriptor);
    cout << "--------------------------------------" << endl;
    cout << "DONE" << endl;
    return 0;

}





/**
 * @brief 
 * 
 * @param args 
 * @param header 
 * @param packet 
 *
 * Disclaimer - structure is inspiried by https://www.tcpdump.org/other/sniffex.c and https://www.tcpdump.org/pcap.html
 * which serves as demonstration of PCAP library usage. See bottom of source code for more details about the original work.
 * 
 *      
 *      Copyright (c) 2005 The Tcpdump Group
 *      timcarst@yahoo.com
 *
 */
void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char *packet)
{
    //init structs - see web for constants
    struct ip *ip; // = (struct ip*)(packet + SIZE_ETHERNET);
    int ip_hdr_len;
    struct ip6_hdr* ip6_hdr;
    int ip6_hdr_len = 40;
    struct udphdr *udp_hdr;
    struct tcphdr *tcp_hdr;
    //payload string
    string payload;
    //init flags for IP version/arp
    bool ipv4_flag = false;
    bool ipv6_flag = false;



    cout << endl;
    cout << "--------------------------------------" <<endl;
    //cout << "Jacked a packet of length: " << header->len << " " << header->caplen << " " << header->ts.tv_sec << ":"<<header->ts.tv_usec <<endl; 
    //struct ether_arp *eth_arp = (ether_arp*)packet;
    
    //print frame size
    cout << "FRAME SIZE: " << header->len << " ON WIRE, " << header->caplen << " CAPTURED"<< endl;

    //format and print timestamp
    int time_buff_size = 30;
    struct tm *tm_sec = localtime(&(header->ts.tv_sec));
    //struct tm *tm_usec = localtime(&(header->ts.tv_usec));
    //printf("%s,",ctime((const time_t*)&header->ts.tv_sec));
    char time_sec_char[time_buff_size];
    //char time_usec_char[time_buff_size];
    strftime(time_sec_char, time_buff_size, "%d.%m.%Y %H:%M:%S", tm_sec);
    //strftime(time_usec_char, time_buff_size, "%f", tm_usec);

    cout << "TIMESTAMP: " << time_sec_char /*<< ":"<< time_usec_char*/;
    printf(".%06ld\n", (long int) header->ts.tv_usec);
    //init ether header struct
    struct ether_header *eth_header = (ether_header*)packet;

    //parsing mac address -- siplest medieval c way - taken from https://stackoverflow.com/questions/4265016/conversion-of-ethernet-address-to-readable-form
    printf("SRC MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned)eth_header->ether_shost[0],
    (unsigned)eth_header->ether_shost[1],
    (unsigned)eth_header->ether_shost[2],
    (unsigned)eth_header->ether_shost[3],
    (unsigned)eth_header->ether_shost[4],
    (unsigned)eth_header->ether_shost[5]);
    printf("DST MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
    (unsigned)eth_header->ether_dhost[0],
    (unsigned)eth_header->ether_dhost[1],
    (unsigned)eth_header->ether_dhost[2],
    (unsigned)eth_header->ether_dhost[3],
    (unsigned)eth_header->ether_dhost[4],
    (unsigned)eth_header->ether_dhost[5]);

    //address buffers
    char src_4[INET_ADDRSTRLEN];
    char dst_4[INET_ADDRSTRLEN];
    char src_6[INET6_ADDRSTRLEN];
    char dst_6[INET6_ADDRSTRLEN];
    //parse IP version/arp and set flags/print arp message
    if(ntohs(eth_header->ether_type) == ETHERTYPE_IP)
    {
        cout << "IP VERSION: IPv4" << endl;
        //set hdr struct
        ipv4_flag = true;
        ip = (struct ip*)(packet + SIZE_ETHERNET);
        ip_hdr_len = ip->ip_p * 4;
        //get and print address
        inet_ntop(AF_INET, &ip->ip_src, src_4, INET_ADDRSTRLEN);
        cout << "SRC IP: " << src_4 << endl;
        inet_ntop(AF_INET, &ip->ip_dst, dst_4, INET_ADDRSTRLEN);
        cout << "DST IP: " << dst_4 << endl;
    } 
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6)
    {
        cout << "IP VERSION: IPv6" << endl;
        ipv6_flag = true;
        ip6_hdr = (struct ip6_hdr*)(packet + SIZE_ETHERNET);
        ip6_hdr_len = 40;
        inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_6, INET6_ADDRSTRLEN);
        cout << "SRC IP: " << src_6 << endl;
        inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_6, INET6_ADDRSTRLEN);
        cout << "DST IP: " << dst_6 << endl;

    }
    else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP)
    {
        cout << "ARP PACKET" << endl;
        struct arphdr *arp_hdr = (struct arphdr*)(packet+SIZE_ETHERNET);
        cout << "OPCODE: " << arp_hdr->ar_op << endl;
        return;
    }


    // if(ip_hdr_len < 20)
    // {
    //     cout << "WARNING: Ip header less than 20" << ip_hdr_len <<endl;
    // }

    //print src & dst IP addresses


    //cout << "V4 flag: " << ipv4_flag << " V6 flag: " << ipv6_flag << " ARP flag: " << arp_flag <<endl;


    //print protocol type in switch from ip structure
    u_char* data;
    int data_len;
    cout << "PROTOCOL TYPE: ";
    
    
    switch(ipv4_flag ? ip->ip_p : ip6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt) {
        //transport layer protocol parsing inspired by http://www.tcpdump.org/pcap.html.
		case IPPROTO_TCP:
            //parse tcp packet
			cout << "TCP" << endl;
            //set struct with offset: eth + ip
            if(ipv4_flag)
            {
                tcp_hdr = (struct tcphdr*)(packet + SIZE_ETHERNET + ip_hdr_len);
            }
            else if(ipv6_flag)
            {
                tcp_hdr = (struct tcphdr*)(packet + SIZE_ETHERNET + ip6_hdr_len);
            }
            //print ports
            cout << "SRC PORT: " << ntohs(tcp_hdr->th_sport) << endl;
            cout << "DST PORT: " << ntohs(tcp_hdr->th_dport) << endl;
            //calculate data segment attributes
            //offset

            data = (u_char*)packet;
            data_len = header->len;
            
            if(data_len > 0)
            {
                cout << "DATA: " << endl;
                print_data(data, data_len);
            }
			break;

		case IPPROTO_UDP:
			cout << "UDP" << endl;
            //set struct with offset: eth + ip
            if(ipv4_flag)
            {
                udp_hdr = (struct udphdr*)(packet + SIZE_ETHERNET + ip_hdr_len);
            }
            else if(ipv6_flag)
            {
                udp_hdr = (struct udphdr*)(packet + SIZE_ETHERNET + ip6_hdr_len);
            }
            //print ports
            cout << "SRC PORT: " << ntohs(udp_hdr->uh_sport) << endl;
            cout << "DST PORT: " << ntohs(udp_hdr->uh_dport) << endl;
            
            data = (u_char*)packet;
            data_len = header->len;

            if(data_len > 0)
            {
                cout << "DATA: " << endl;
                print_data(data, data_len);
            }
			break;
		
        case IPPROTO_ICMP:
            if(ipv4_flag)
            {
                cout << "ICMP" << endl;
                data = (u_char*)packet;
                data_len = header->len;
                if(data_len > 0)
                {
                    cout << "DATA: " << endl;
                    print_data(data, data_len);
                }
            }
            break;

        case IPPROTO_ICMPV6:
            if(ipv6_flag)
            {
                cout << "ICMP" << endl;
                data = (u_char*)packet;
                data_len = header->len;
                if(data_len > 0)
                {
                    cout << "DATA: " << endl;
                    print_data(data, data_len);
                }
            }
			break;

		default:
			cout << "unknown: " << ip->ip_p <<  endl;
			return;
	}

}
// end of inspired code 

/**
 * @brief Printing function code fully form https://www.tcpdump.org/other/sniffex.c. See bottom of source code for more details.
 *      Copyright (c) 2005 The Tcpdump Group
 *      timcarst@yahoo.com
 * 
 * @param payload data ptr
 * @param len data len
 */
void print_data(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + 10;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}
//end of fully reused code from https://www.tcpdump.org/other/sniffex.c

/**
 * @brief Printing helper function code fully from https://www.tcpdump.org/other/sniffex.c See bottom of source code for more details.
 *      Copyright (c) 2005 The Tcpdump Group
 *      timcarst@yahoo.com
 * 
 * @param payload data
 * @param len data len
 * @param offset offset
 */
void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("0x%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}
//end of fully reused code



/**
 * @brief cleans resources and exits
 * 
 * @param s for signal()
 */
void clean_up(int s)
{
    pcap_close(dev_descriptor);
    cerr << endl << "Sniffer terminated -- resources freed." << endl;
    
    exit(0);
}



/**
 * @brief generates formated pcap filter
 * 
 * @param udp  udp flag
 * @param tcp tcp flag
 * @param port port num (-1 -> all)
 * @param arp arp flag
 * @param icmp icmp flag
 * @return string formated pcap filter string
 */
string load_filter(int udp, int tcp, int port, int arp, int icmp)
{
    string filter = "";
    string port_s = to_string(port);
    bool use_or = false;

    //port specified
    if(port >= 0)
    {
        if(udp)
        {
            filter.append("(udp port " + port_s + ")");
            use_or = true;
        }
        if(tcp)
        {
            if(use_or)
            {
                filter.append(" or ");
            }
            filter.append("(tcp port " + port_s + ")");
            use_or = true;
        }
    }
    //port unspecified
    else 
    {
        if(udp)
        {
            filter.append("udp");
            use_or = true;
        }
        if(tcp)
        {
            if(use_or)
            {
                filter.append(" or ");
            }
            filter.append("tcp");
            use_or = true;
        }
    }
    //icmp parsing
    if(icmp)
    {   
        if(use_or)
        {
            filter.append(" or ");
        }
        filter.append("icmp or icmp6");
        use_or = true;
    }
    //arp parsing
    if(arp)
    {
        if(use_or)
        {
            filter.append(" or ");
        }
        filter.append("arp");
        use_or = true;
    }

    //none but port specified
    if(!use_or && port >= 0)
    {
        filter.append("icmp or icmp6 or arp or ((tcp or udp) and port " + port_s + ")");
    }
    //none specified
    else if(!use_or)
    {
        filter.append("icmp or icmp6 or arp or tcp or udp");
    }
    
    return filter;
}


/**
 * @brief Set the pcap handle object
 * 
 * @param dev device
 * @param filter filter
 * @return pcap_t* open device
 */
pcap_t* set_pcap_handle(string dev, string filter)
{
    //init necessary pcap vars
    char error_buffer[PCAP_ERRBUF_SIZE];
    bpf_u_int32 src_ip, net_mask;
    struct bpf_program bpf_p;

    //get iface netmask and ip for filter
    if(pcap_lookupnet(dev.c_str(), &src_ip, &net_mask, error_buffer) < 0)
    {
        cerr << "ERROR during address lookup, pcap: " << error_buffer << endl;
        exit(ERROR);
    }

    //open device for capturing traffic   
    pcap_t *dev_descriptor; 
    if((dev_descriptor = pcap_open_live(dev.c_str(), BUFSIZ, 1, 1000, error_buffer)) == NULL)
    {
        cerr << "ERROR during handle creating, pcap: " << error_buffer << " Try running as root. " <<endl;
        exit(ERROR);
    }

    // if(pcap_activate(dev_descriptor) < 0){
    //     cerr << "Could not activate "<<endl;
    // }

    //compile a filter from string 
    if(pcap_compile(dev_descriptor, &bpf_p, filter.c_str(), 0, net_mask) < 0 )
    {
        cerr << "ERROR during filter compilation, pcap: " << error_buffer << endl;
        exit(ERROR);
    }

    //aply filter from the compile bpf_p filter
    if(pcap_setfilter(dev_descriptor, &bpf_p) < 0)
    {
        cerr << "ERROR during filter aplying, pcap: " << error_buffer << endl;
        exit(ERROR);
    }
    
    return dev_descriptor;
}

/**
 * @brief Prints the default help message and terminates the program
 * @param parameter name of the program (argv[0])
 */
void print_help(char* progname)
{
    cout << "Sniffer usage: " << progname << "[options..]" << endl;
    cout << "\t-i, --interface <string>  Specifies target interface. Prints interfaces when without argument." << endl;
    cout << "\t-p <unsigned>             Specifies target port. Uses all ports when not set." << endl;
    cout << "\t-t, --tcp                 Prints only TCP packets. Cant be combined with -u. View all when unset." << endl;
    cout << "\t-u, --udp                 Prints only UDP packets. Cant be combined with -t. View all when unset." << endl;
    cout << "\t--icmp                    Prints only ICMPv4 and IDMPv6 packets. Views all when unspecified." << endl;
    cout << "\t--arp                     Prints only ARP frames. Views all when unspecified." << endl;
    cout << "\t-n, --number <unsigned>   Prints selected positive number of packets. Prints 1 when unspecified." << endl;
    cout << "\t-h, --help                Prints this message." << endl;
    cout << "Have fun!" << endl;

    exit(SUCCES);
}


/**
 * @brief Prints interface when -i switch is used without param
 */
void print_interfaces()
{
    //init err buffer
    char error_buffer[PCAP_ERRBUF_SIZE];
    //init IF pointers
    pcap_if_t *aviable_interfaces;
    
    //load interfaces and check for correct execution - loads linked list into aviable interfaces
    if (pcap_findalldevs(&aviable_interfaces, error_buffer) < 0) {
        cerr << "ERROR: Internal PCAP lib error when searching for interfraces";
        exit(ERROR);
    }

    //print all interfaces - linked list looping
    auto *tmp = aviable_interfaces;
    while(tmp != NULL)
    {
        cout << tmp->name <<endl;
        tmp = tmp->next;
    }
    //free devices
    pcap_freealldevs(aviable_interfaces);
    exit(SUCCES);
}



///////////////////////////////////////////////////////////////////////////
// INFORMATION REGARDING FUNCTIONS REUSED/MODIFIED CODE
///////////////////////////////////////////////////////////////////////////
/*
 * sniffex.c
 *
 * Sniffer example of TCP/IP packet capture using libpcap.
 *
 * Version 0.1.1 (2005-07-05)
 * Copyright (c) 2005 The Tcpdump Group
 *
 * This software is intended to be used as a practical example and
 * demonstration of the libpcap library; available at:
 * http://www.tcpdump.org/
 *
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 *
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 *
 * "sniffer.c" is distributed under these terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 *
 * This software, "sniffex.c", is a derivative work of "sniffer.c" and is
 * covered by the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Because this is a derivative work, you must comply with the "sniffer.c"
 *    terms reproduced above.
 * 2. Redistributions of source code must retain the Tcpdump Group copyright
 *    notice at the top of this source file, this list of conditions and the
 *    following disclaimer.
 * 3. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The names "tcpdump" or "libpcap" may not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM.
 * BECAUSE THE PROGRAM IS LICENSED FREE OF CHARGE, THERE IS NO WARRANTY
 * FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW.  EXCEPT WHEN
 * OTHERWISE STATED IN WRITING THE COPYRIGHT HOLDERS AND/OR OTHER PARTIES
 * PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED
 * OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  THE ENTIRE RISK AS
 * TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.  SHOULD THE
 * PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING,
 * REPAIR OR CORRECTION.
 *
 * IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW OR AGREED TO IN WRITING
 * WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MAY MODIFY AND/OR
 * REDISTRIBUTE THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES,
 * INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING
 * OUT OF THE USE OR INABILITY TO USE THE PROGRAM (INCLUDING BUT NOT LIMITED
 * TO LOSS OF DATA OR DATA BEING RENDERED INACCURATE OR LOSSES SUSTAINED BY
 * YOU OR THIRD PARTIES OR A FAILURE OF THE PROGRAM TO OPERATE WITH ANY OTHER
 * PROGRAMS), EVEN IF SUCH HOLDER OR OTHER PARTY HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES.
 * <end of "sniffex.c" terms>
 */