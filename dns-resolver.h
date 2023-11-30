/**
 * @author Rostislav Kral
 * @brief Contains DNS packet structures, DNS types and DnsResolver Class.
 * @file dns-resolver.h
 * */

#include <iostream>
#include <cstring>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <vector>
#include <unistd.h>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include "helpers.h"


#define MAX_DNS_SIZE 512 // Maximal UDP size for DNS packet

#define T_A 1 //Ipv4 address
#define T_NS 2 //Nameserver
#define T_CNAME 5 // canonical name
#define T_SOA 6 /* start of authority zone */
#define T_PTR 12 /* domain name pointer */
#define T_MX 15 //Mail server
#define T_AAAA 28 // IPv6 address

#pragma pack(push, 1)

//DNS header packet structure from RFC 1035 + checking the byte order
struct DNS_HEADER {
    unsigned id: 16;

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    unsigned qr :1;
    unsigned opcode :4;
    unsigned aa :1;
    unsigned tc :1;
    unsigned rd :1;
    unsigned ra :1;
    unsigned reserved :3;
    unsigned rcode :4;
#else // LITTLE_ENDIAN
    unsigned rd: 1;
    unsigned tc: 1;
    unsigned aa: 1;
    unsigned opcode: 4;
    unsigned qr: 1;
    unsigned rcode: 4;
    unsigned reserved: 3;
    unsigned ra: 1;
#endif

    unsigned qdcount: 16;
    unsigned ancount: 16;
    unsigned nscount: 16;
    unsigned arcount: 16;

};

//DNS question structure
struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
};

//Arguments from the command line
struct Args {
    bool recursion = false;
    bool reverse = false;
    bool use_ipv6 = false;
    char *server = nullptr;
    int port = 53;
    std::string domain;
};


class DnsResolver {
public:
    /**
     * @brief Constructor of the DnsResolver, saving the Args structure
     * @param args
     * */
    explicit DnsResolver(Args args);

    /**
     * @brief This method will try to establish the connection to DNS server
     * @return
     * */
    void connectToDNSServer();

    /**
     * @brief Creation of the DNS Question and sending it to DNS server
     * @return
     * */
    void query();

    /**
     * @brief Printing the whole received DNS packet in HEX format
     * @return
     * */
    void printData();

    /**
     * @brief Parsing all answer sections and storing them in DNS_INFO structure which is going to be returned back to method caller for further usage.
     * @return DNS_INFO
     * */
    DNS_INFO getAnswer();

    /**
     * @brief Taking the DNS_INFO structure and printing it in human-readable format to console.
     * @return
     * */
    void printAnswer(DNS_INFO info);

private:
    int sock;
    Args args;
    // Buffer initialization
    struct DNS_HEADER *dns = NULL;
    unsigned char buf[MAX_DNS_SIZE];
    int packetSize;
    struct QUESTION *qinfo = NULL;

};

