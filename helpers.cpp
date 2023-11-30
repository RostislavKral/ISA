/**
 * @author Rostislav Kral
 * @brief Contains implementations of helper structures and functions for resolver.
 * @file helpers.h
 * */


#include "helpers.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// Taken from: https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/
void ChangeToDnsNameFormat(unsigned char *dns, unsigned char *host) {
    size_t lock = 0;
    strcat((char *) host, ".");

    for (size_t i = 0; i < strlen((char *) host); i++) {
        if (host[i] == '.') {
            *dns++ = i - lock;
            for (; lock < i; lock++) {
                *dns++ = host[lock];
            }
            lock++; //or lock=i+1;
        }
    }
    *dns++ = '\0';

}

std::vector<std::string> explode(std::string const &s, char delim) {
    std::vector<std::string> result;
    std::istringstream iss(s);

    for (std::string token; std::getline(iss, token, delim);) {
        result.push_back(std::move(token));
    }

    return result;
}

std::string buildPTRQuery(const std::string &ipAddress) {
    std::string ptrQuery;
    struct in6_addr ipv6Address;
    struct in_addr ipv4Address;
    bool useIPv6;

    // Trying to convert std::string ipAddress to IPv4 format
    if (inet_pton(AF_INET, ipAddress.c_str(), &ipv4Address) == 1) {
        useIPv6 = false;
    }
        // Trying to convert std::string ipAddress to IPv6 format
    else if (inet_pton(AF_INET6, ipAddress.c_str(), &ipv6Address) == 1) {
        useIPv6 = true;
    }
        // In case of that the IP address has invalid format
    else {
        std::cerr << "Invalid IP address!" << std::endl;
        exit(-1);
    }


    if (useIPv6) {
        // For example the IPv6 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        // is going to be reversed to PTR domain: "4.3.3.7.0.7.3.0.e.2.a.8.8.0.0.0.0.3.5.a.8.8.b.d.0.1.0.0.2.ip6.arpa"
        if (inet_pton(AF_INET6, ipAddress.c_str(), &ipv6Address) == 1) {
            char reversedIP[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &ipv6Address, reversedIP, INET6_ADDRSTRLEN) != nullptr) {
                std::string tmp = std::string(reversedIP);
                std::string::difference_type n = std::count(tmp.begin(), tmp.end(), ':');
                std::vector<std::string> s = explode(tmp, ':');

                for (int octet = s.size() - 1; octet >= 0; octet--) {
                    if (s[octet].empty()) {
                        for (int i = 0; i < 8 - n; ++i) {
                            for (int j = 0; j < 4; j++) {
                                ptrQuery.append("0.");
                            }
                        }
                    } else {
                        for (int i = s[octet].length() - 1; i >= 0; i--) {

                            char c = (const char) s[octet][i];

                            ptrQuery.append(1, c);
                            ptrQuery.append(".");
                        }
                        if (s[octet].length() - 1 != 3) {
                            for (int i = 0; i < 4 - s[octet].length(); ++i) {
                                ptrQuery.append("0.");
                            }
                        }
                    }
                }
                ptrQuery.append("ip6.arpa");
            }
        }
    } else {
        // IPv4
        // For example IPv4 address: 192.0.2.1
        // is going to be converted to PTR domain: "1.2.0.192.in-addr.arpa"
        if (inet_pton(AF_INET, ipAddress.c_str(), &ipv4Address) == 1) {
            char reversedIP[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &ipv4Address, reversedIP, sizeof(reversedIP)) != nullptr) {
                std::vector<std::string> s;
                s = explode(std::string(reversedIP), '.');
                for (size_t i = s.size() - 1; i < -1; i--) {
                    ptrQuery.append(s[i]);
                    ptrQuery.append(".");
                }
                ptrQuery.append("in-addr.arpa");
            }
        }
    }

    return ptrQuery;
}

// The logic is taken from: https://www.binarytides.com/dns-query-code-in-c-with-linux-sockets/ and transformed into C++ from C
void parseName(const unsigned char *reader, const unsigned char *buffer, std::string &name) {
    unsigned int p = 0, jumped = 0, offset;
    int i, j;

    name.clear();

    while (*reader != 0) {
        if (*reader >= 192) { // 192 = 11000000, means it is a name with pointer
            offset = (*reader) * 256 + *(reader + 1) - 49152; // 49152 = 11000000 00000000
            reader = buffer + offset - 1;
            jumped = 1; // we have jumped to another location so counting it
        } else {
            name.push_back(*reader);
        }

        reader = reader + 1;

        if (jumped == 0) {
            p = p + 1; // if we haven't jumped to another location then increase the counter
        }
    }

    // now convert 3www6google3com0 to www.google.com
    for (i = 0; i < name.size(); i++) {
        int len = name[i];
        for (j = 0; j < len; j++) {
            name[i] = name[i + 1];
            i = i + 1;
        }
        name[i] = '.';
    }
    name[i - 1] = '\0'; // remove the last dot
}
