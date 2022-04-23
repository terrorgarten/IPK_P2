//#include <bits/getopt_core.h>
//#include <cstddef>
#include <cstddef>
#include <cstdio>
#include <exception>
#include <getopt.h>
#include <iostream> 	            //parse args
#include <ostream>
#include <pcap.h>
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

#define SUCCES  0
#define ERROR   1

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
                cout << "Port: " << port << endl;
                break;

            case 't':
                //set TCP flag
                tcp_flag = 1;
                cout << "TCP set" << endl;
                break;

            case 'u':
                //set UDP flag
                udp_flag = 1;
                cout << "UDP set" << endl;
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
                cout << "Packet count set " << packet_num << endl;
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
    cout << udp_flag << icmp_flag << tcp_flag << arp_flag << interface <<endl;

    
    
    //check if iface was set correctly 
    //TODO dead code?
    if(interface.empty())
    {
        cerr << "ERROR: No interface [-i|--interface] was specified. Use -h for help" << endl;
    }

    //loads a filter string depending on flags
    string filter = load_filter(udp_flag, tcp_flag, port, arp_flag, icmp_flag);
    cout << port <<endl;
    cout << "FILTER: " << filter;
    
    //trap sigint for correct freeing of memmory
    signal(SIGINT, clean_up);

    //sets up the device descriptor
    dev_descriptor = set_pcap_handle(interface, filter);
    
    cout << "preloopoid"<<packet_num << endl;

    int datalink_type;
    if((datalink_type = pcap_datalink(dev_descriptor) < 0))
    {
        cerr << "ERROR: Could not determine datalink layer type. (pcap_datalink)";
        exit(ERROR);
    }


    //check for the type of datalink and accept only ethernet
    if(datalink_type != DLT_EN10MB)
    {
        cerr << "Invalid datalink type - currently only Ethernet (EN10MB) is supported. " << endl;
        exit(ERROR);
    }

    //runs main loop for catching packets
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_loop(dev_descriptor, packet_num, handle_packet, NULL) < 0)
    {
        cerr << "Error during packet read loop, pcap: " << errbuf << endl;
        exit(ERROR);
    };

    pcap_close(dev_descriptor);
    cout << "DONE"<<endl;
    return 0;

}






void handle_packet(u_char* args, const struct pcap_pkthdr* header, const u_char *packet)
{
    cout << "PACKETOZA" <<endl; 
}

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
    // //check conflict void print_help()on args
    // // if(udp && tcp)
    // // {
    // //     cerr << "ERROR: Unvalid argument combination: [-t|--tcp] and [-u|--udp]";
    // //     exit(ERROR);
    // // }
    string filter = "";
    string port_s = to_string(port);
    bool use_or = false;

    //
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
    if(!use_or && port >= 0)
    {
        filter.append("Icmp or icmp6 or arp or ((tcp or udp) and port " + port_s + ")");
    }


    if(icmp)
    {   
        if(use_or)
        {
            filter.append(" or ");
        }
        filter.append("icmp or icmp6");
        use_or = true;
    }
    if(arp)
    {
        if(use_or)
        {
            filter.append(" or ");
        }
        filter.append("arp");
    }
    
    return filter;
}

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
    if((dev_descriptor = pcap_open_live(dev.c_str(), BUFSIZ, 1, 0, error_buffer)) == NULL)
    {
        cerr << "ERROR during handle creating, pcap: " << error_buffer << endl;
        exit(ERROR);
    }

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

/**
 * use caplen not len- pro delku framu v bytech, presne tak jak je
 * -- nejspise neobsahuje CRC checksum
 * pcap_next() - vrati jeden paket, lze nastavit timeout
 * timestampy - Z jako centralni cas
 * ntohs, ntohl . pro spravne vypisy hodnot
 * pcap_geterr -> vrati last command error
 * inet_ntop -. vypisovani ipv4/6 adres 198.142.234, dava pole charu !!! pro ipv6 dat velky buffer at nedela bordel
 * 
 */
