/**
 * @author Rostislav Kral
 * @brief Contains helper structures and functions for resolver.
 * @file helpers.h
 * */


#include <vector>
#include <cstring>
#include <iostream>
#include <sstream>
#include <arpa/inet.h>
#include <algorithm>


/**
 * @brief Helper structure for storing particular DNS records
 * */
struct DNS_REC {

    int ttl;
    std::string name;
    std::string type;
    std::string value; // IP or CNAME

};

/**
 * @brief Structure for storing information about parsed DNS packet
 * */
struct DNS_INFO {
    int qdcount;
    int ancount;
    int arcount;
    int nscount;


    std::string aa;
    std::string rd;
    std::string tc;

    std::string questionName;
    std::string type;

    std::vector<DNS_REC> answers;
    std::vector<DNS_REC> additionals;
    std::vector<DNS_REC> authorities;
};


void ChangeToDnsNameFormat(unsigned char *dns, unsigned char *host);

void parseName(const unsigned char *reader, const unsigned char *buffer, std::string &name);

/**
 * @brief Functions for converting string to array of strings via delimiter.
 * @param s Reference of the input string that is going to be exploded.
 * @param delim Delimiter, I am allowing only char value
 * @return std::vector<std::string> vector of exploded strings
 * */
std::vector<std::string> explode(std::string const &s, char delim);

/**
 * @brief Helper function for building PTR query, i.e. reversing the string/IP and putting .in-addr.arpa or .ip6.arpa based on type of the IP address
 * @param ipAddress The IP address that is going to be reversed.
 * @return std::string
 * */
std::string buildPTRQuery(const std::string &ipAddress);

