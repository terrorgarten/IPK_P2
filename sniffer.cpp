//#include <bits/getopt_core.h>
//#include <cstddef>
#include <cstdlib>
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



// struct option longopts[] = {
//    { "all",     no_argument,       & do_all,     1   },
//    { "file",    required_argument, NULL,         'f' },
//    { "help",    no_argument,       & do_help,    1   },
//    { "verbose", no_argument,       & do_verbose, 1   },
//    { 0, 0, 0, 0 }
// };

void print_interfaces();

void print_help();


int main(int argc, char* argv[])
{
    //interface specificator
    char* interface;
    //port specificator, -1 when all
    int port = -1;
    //flag for tcp only mode
    int tcp_flag = 0;
    //flag for udp only mode
    int udp_flag = 0;
    //packet number specifier, 1 when default
    int packet_num = 1;

    //cmd line argument
    int cla;
    //cla loading loop
    while((cla = getopt(argc, argv, "i::p:tun")) != -1)
    {
        cout << "caught switch" << endl;
        switch (cla) 
        {
            case 'i':
                if(optarg == NULL)
                {   
                    // -i without param -> print interfaces
                    cout << "-i empty"<<endl;
                    print_interfaces();
                }
                else 
                {   
                    cout << "-i set";
                    //copy the interface callname into the specifier var
                    strcpy(interface, optarg);
                    //printf("interface: %s", interface);
                    cout << "Interface: " << interface << endl;
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
        }
         
    
    }

    //check conflict void print_help()on args
    if(udp_flag && tcp_flag)
    {
        cerr << "Unvalid argument combination: [-t|--tcp] and [-u|--udp]";
        exit(ERROR);
    }

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
    printf("INTERFACES");
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
