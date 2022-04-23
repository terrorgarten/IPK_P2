//#include <bits/getopt_core.h>
//#include <cstddef>
#include <cstddef>
#include <getopt.h>
#include <iostream> 	            //parse args
#include <ostream>
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

#define SUCCES  0
#define ERROR   1

//std namespace
using namespace std;

/*Global flags for options*/



// struct option longopts[] = {
//    { "all",     no_argument,       & do_all,     1   },
//    { "file",    required_argument, NULL,         'f' },
//    { "help",    no_argument,       & do_help,    1   },
//    { "verbose", no_argument,       & do_verbose, 1   },
//    { 0, 0, 0, 0 }
// };

void print_interfaces();

void print_help(char* progname);



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
    //interface specificator
    string interface = "";
    //port specificator, -1 when all
    int port = -1;
    //packet number specifier, 1 when default
    int packet_num = 1;
    //cmd line argument
    int cla;
    //index
    extern int optind;
    //cla loading loop
    while((cla = getopt_long(argc, argv, short_opt, long_opt, &optind)) != -1)
    {
        cout << "Caught arg " << optind  << endl;
        char* tmp_optarg = NULL;
        switch (cla) 
        {
            //flag set
            case 0:
                break;
            case 'i':
                if(!optarg && argv[optind] != NULL && '-' != argv[optind][0])
                {   
                    tmp_optarg = argv[optind];                   
                }
                if(tmp_optarg){
                    cout << "OK: " << tmp_optarg << endl;
                }
                else 
                {   
                    // -i without param -> print interfaces
                    cout << "-i empty"<<endl;
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
                packet_num = stoi(optarg);
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

    //check conflict void print_help()on args
    if(udp_flag && tcp_flag)
    {
        cerr << "ERROR: Unvalid argument combination: [-t|--tcp] and [-u|--udp]";
        exit(ERROR);
    }
    cout << udp_flag << icmp_flag << tcp_flag << arp_flag <<endl;
    return 0;
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
    cout << "print_interfaces called" << endl;
    exit(SUCCES);
}

/**
 * use caplen not len- pro delku framu v bytech, presne tak jak je
 * -- nejspise neobsahuje CRC checksum
 * pcap_next() - vrati jeden paket, lze nastavit timeout
 * timestampy - Z jako centralni cas
 * ntohs, ntohl . pro pravne vypisy hodnot
 * pcap_geterr -> vrati last command error
 * inet_ntop -. vypisovani ipv4/6 adres 198.142.234, dava pole charu !!! pro ipv6 dat velky buffer at nedela bordel
 * 
 */
