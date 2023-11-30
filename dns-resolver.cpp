/**
 * @author Rostislav Kral
 * @brief Main logic of the resolver, this file contains implementations of the DnsResolver class.
 * @file dns-resolver.cpp
 * */

#include "dns-resolver.h"

DnsResolver::DnsResolver(Args args)
{
    this->args = args;
    memset(buf, 0, sizeof(buf));
}

void DnsResolver::connectToDNSServer()
{
    struct addrinfo hints, *result, *tmp;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    // Trying to get addresses of the DNS server
    if ((getaddrinfo(args.server, std::to_string(args.port).c_str(), &hints, &result)) != 0)
    {
        perror("Cannot fetch given dns server!\n");
        exit(1);
    }

    tmp = result;

    while (result != NULL)
    {
        if (result->ai_family == AF_INET || result->ai_family == AF_INET6)
        {
            if ((this->sock = socket(result->ai_family, SOCK_DGRAM, 0)) == -1)
            {
                perror("Socket creation failed\n");
                exit(1);

            }
            if ((connect(sock, result->ai_addr, result->ai_addrlen)) == -1)
            {
                perror("DNS server unreachable\n");
                exit(1);

            }

            break;
        }
        result = result->ai_next;
    }

    if (result == NULL)
    {
        perror("DNS server not found\n");
        exit(1);
    }

    freeaddrinfo(tmp);
}

void DnsResolver::query()
{
    // ---------------------------------       QUESTION SECTION QUERY             ----------------------------------

    unsigned char *qname;

    dns = (struct DNS_HEADER *)&buf;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;                      // This is a query
    dns->opcode = 0;                  // This is a standard query
    dns->aa = 0;                      // Not Authoritative
    dns->tc = 0;                      // This message is not truncated
    dns->rd = args.recursion ? 1 : 0; // Recursion Desired
    dns->ra = 0;                      // Recursion not available
    dns->rcode = 0;
    dns->qdcount = htons(1); // we have only 1 question
    dns->ancount = 0;
    dns->arcount = 0;
    dns->nscount = 0;

    qname = (unsigned char *)&buf[sizeof(struct DNS_HEADER)];
    if (args.reverse)
        args.domain = buildPTRQuery(args.domain);
    ChangeToDnsNameFormat(qname, (unsigned char *)args.domain.c_str()); // Need to parse the domain to DNS format
    qinfo = (struct QUESTION *)&buf[sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1)];

    if (args.reverse)
        qinfo->qtype = htons(T_PTR);
    else
        qinfo->qtype = args.use_ipv6 ? htons(T_AAAA) : htons(T_A); // type of the query

    qinfo->qclass = htons(1); // IN

    if (send(sock, (char *)buf,
             sizeof(struct DNS_HEADER) + (strlen((const char *)qname) + 1) + sizeof(struct QUESTION), 0) < 0)
    {
        perror("Send failed");
        exit(1);
    }

    if ((packetSize = recv(sock, buf, MAX_DNS_SIZE, 0)) < 0)
    {
        perror("Failed to receive");
        exit(1);
    }

    // Close the socket
    close(sock);

    //  ----------------------------- END OF QUESTION QUERY SECTION ---------------------------------
}

void DnsResolver::printData()
{
    // -------- HEX Data output -----------------
    int row = 0;
    std::cout << "00" << row << "0:     ";
    for (int i = 0; i < packetSize; i++)
    {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(buf[i]) << " ";
        if ((i + 1) % 16 == 0)
        {
            row++;
            std::cout << std::endl;

            std::cout << "00" << row << "0:     ";
        }
    }
    std::cout << std::dec << std::endl
              << std::endl;

    // --------------- END OF HEX Data output -----------------
}

DNS_INFO DnsResolver::getAnswer()
{

    DNS_INFO dnsInfo;

    // ---------------------------------------------- DNS HEADER PARSING ---------------------------------------------------------
    DNS_HEADER *dnsHeader = reinterpret_cast<DNS_HEADER *>(buf);
    //    uint16_t id = ntohs(dnsHeader->id);
    uint16_t qdcount = ntohs(dnsHeader->qdcount);
    uint16_t ancount = ntohs(dnsHeader->ancount);
    uint16_t arcount = ntohs(dnsHeader->arcount);
    uint16_t nscount = ntohs(dnsHeader->nscount);

    dnsInfo.qdcount = qdcount;
    dnsInfo.ancount = ancount;
    dnsInfo.arcount = arcount;
    dnsInfo.nscount = nscount;

    std::string aa, rd, tc;
    aa = (ntohs(dnsHeader->aa) ? "Yes" : "No");
    rd = (ntohs(dnsHeader->rd) ? "Yes" : "No");
    tc = (ntohs(dnsHeader->tc) ? "Yes" : "No");

    dnsInfo.aa = aa;
    dnsInfo.rd = rd;
    dnsInfo.tc = tc;

    int offset = 12; // RFC1035 DNS header packet structure
    const unsigned char *questionPtr = buf + sizeof(DNS_HEADER);

    // ---------------------------------------------- END OF DNS HEADER PARSING ---------------------------------------------------------

    // ---------------------------------------------- DNS QUESTION PARSING --------------------------------------------------------------
    // Parse QNAME
    int questionLength = 0;
    std::string questionName;
    while (questionPtr[questionLength] != 0)
    {
        int labelLength = questionPtr[questionLength];
        for (int i = 0; i < labelLength; i++)
        {
            questionName += questionPtr[questionLength + i + 1];
        }
        questionLength += labelLength + 1;
        questionName += ".";
    }

    dnsInfo.questionName = questionName;

    std::string type;
    if (ntohs(qinfo->qtype) == T_A)
        type = "A";
    else if (ntohs(qinfo->qtype) == T_AAAA)
        type = "AAAA";
    else if (ntohs(qinfo->qtype) == T_PTR)
        type = "PTR";

    questionPtr += questionLength + 5;

    dnsInfo.type = type;

    // ---------------------------------------------- END OF DNS QUESTION PARSING --------------------------------------------------------------

    // ----------------------------------------------- DNS ANSWERS SECTION PARSING -------------------------------------------------------------
    const unsigned char *answerPtr = questionPtr;
    uint16_t rdlength;
    for (int i = 0; i < ancount; i++)
    {
        uint16_t type;
        uint32_t ttl;
        DNS_REC record;
        std::string parsedName;

        // Parse TYPE
        memcpy(&type, answerPtr + 2, sizeof(uint16_t));
        type = ntohs(type);
        // Parse TTL
        memcpy(&ttl, answerPtr + 6, sizeof(uint32_t));
        ttl = ntohl(ttl);
        record.ttl = ttl;

        // Parse RDLENGTH
        memcpy(&rdlength, answerPtr + 10, sizeof(uint16_t));
        rdlength = ntohs(rdlength);

        // Parse NAME
        if (type != T_CNAME)
        {
            parseName(answerPtr, buf, parsedName);

            if (*answerPtr != 192)
            {
                answerPtr = answerPtr + (parsedName.length() - 1);
            }

            record.name = parsedName;
        }

        // Parse RDATA
        if (type == T_A)
        {
            std::ostringstream stringStream;
            stringStream << (int)*(answerPtr + offset) << "." << (int)*(answerPtr + offset + 1) << "."
                         << (int)*(answerPtr + offset + 2) << "." << (int)*(answerPtr + offset + 3);
            record.value = stringStream.str();
            record.type = "A";
        }
        else if (type == T_AAAA)
        {

            std::ostringstream stringStream;
            std::ostringstream temp;
            int len;

            for(int i = 0; i < 16; i+=2) 
            {
           
                temp << std::hex << ntohs(*reinterpret_cast<const uint16_t *>(answerPtr + offset + i));
                
                len = temp.str().length();
               if(len != 4) {
                    for(int i = 0; i < 4 - len; i++) temp << std::hex << "0";
                }

                
                stringStream << std::hex << temp.str();
                if(i != 14) stringStream << ":";
                temp.str("");

                
            }
            

            record.value = stringStream.str();
            record.type = "AAAA";
        }   
        else if (type == T_CNAME)
        {
            std::string parsedName, parsedCName;

            parseName(answerPtr, buf, parsedCName);
            if (*answerPtr != 192)
            {
                answerPtr = answerPtr + (parsedCName.length() - 1);
            }
            parseName(answerPtr + offset, buf, parsedName);

            record.value = parsedName;
            record.name = parsedCName;

            record.type = "CNAME";
        }
        else if (type == T_PTR)
        {
            int labelLength = 0;
            std::ostringstream stringStream;

            while (answerPtr[labelLength + offset] != 0)
            {
                int currentLabelLength = answerPtr[labelLength + offset];
                for (int j = 0; j < currentLabelLength; j++)
                {
                    stringStream << answerPtr[labelLength + offset + j + 1];
                }
                labelLength += currentLabelLength + 1;
                if (answerPtr[labelLength + offset] != 0)
                    stringStream << ".";
            }

            record.value = stringStream.str();
            record.type = "PTR";
        }
        else
            record.type = "UNSUPPORTED";
        answerPtr += offset + rdlength;

        dnsInfo.answers.push_back(record);
    }
    // ------------------------------------------------------------------- END OF DNS ANSWERS SECTION PARSING ---------------------------------------------------------------------

    const unsigned char *authorityPtr = answerPtr;
    for (int i = 0; i < nscount; i++)
    {
        // Parse NAME
        uint16_t type;
        uint32_t ttl;
        DNS_REC record;
        std::string parsedName, parsedCName;

        parseName(authorityPtr, buf, parsedCName);

        if (*authorityPtr != 192)
        {
            authorityPtr = authorityPtr + (parsedCName.length() - 1);
        }

        parseName(authorityPtr + offset, buf, parsedName);

        // Parse RDLENGTH
        memcpy(&rdlength, authorityPtr + 10, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        // Parse TYPE
        memcpy(&type, authorityPtr + 2, sizeof(uint16_t));
        type = ntohs(type);
        // Parse TTL
        memcpy(&ttl, authorityPtr + 6, sizeof(uint32_t));
        ttl = ntohl(ttl);
        if (type == T_NS)
        {
            record.ttl = ttl;
            record.name = parsedCName;
            record.value = parsedName;
            record.ttl = ttl;
            record.type = "NS";
        }
        else
        {
            record.type = "UNSUPPORTED";
        }

        dnsInfo.authorities.push_back(record);
        authorityPtr += offset + rdlength;
    }

    /* ----------------------------------------------------------- ADDITIONAL SECTION ANSWERS PARSING ------------------------------------------------------------- */
    const unsigned char *additionalPtr = authorityPtr;
    for (int i = 0; i < arcount; i++)
    {
        uint16_t type;
        // uint16_t _class; We do not need it for this project
        uint32_t ttl;
        DNS_REC record;
        std::string parsedName;
        // Parse TYPE

        memcpy(&type, additionalPtr + 2, sizeof(uint16_t));
        type = ntohs(type);
        // Parse TTL
        memcpy(&ttl, additionalPtr + 6, sizeof(uint32_t));
        ttl = ntohl(ttl);
        record.ttl = ttl;

        // Parse RDLENGTH
        memcpy(&rdlength, additionalPtr + 10, sizeof(uint16_t));
        rdlength = ntohs(rdlength);
        // Parse NAME
        if (type != T_CNAME)
        {
            parseName(additionalPtr, this->buf, parsedName);
            if (*answerPtr != 192)
            {
                answerPtr = answerPtr + (parsedName.length() - 1);
            }

            record.name = parsedName;
        }

        //  std::cout << "TYPE::::::::      " << type << std::endl;

        // Parse RDATA
        if (type == T_A)
        {

            std::ostringstream stringStream;
            stringStream << (int)(*(additionalPtr + offset)) << "." << (int)(*(additionalPtr + offset + 1)) << "."
                         << (int)(*(additionalPtr + offset + 2)) << "." << (int)(*(additionalPtr + offset + 3));
            record.value = stringStream.str();
            record.type = "A";
        }
        else if (type == T_AAAA)
        {
            std::ostringstream stringStream;
            std::ostringstream temp;
            int len;

            for(int i = 0; i < 16; i+=2) 
            {
           
                temp << std::hex << ntohs(*reinterpret_cast<const uint16_t *>(additionalPtr + offset + i));
                
                len = temp.str().length();
               if(len != 4) {
                    for(int i = 0; i < 4 - len; i++) temp << std::hex << "0";
                }

                
                stringStream << std::hex << temp.str();
                if(i != 14) stringStream << ":";
                temp.str("");

                
            }
            record.value = stringStream.str();
            record.type = "AAAA";
        }
        else if (type == T_CNAME)
        {

            std::string parsedName, parsedCName;
            parseName(additionalPtr + offset, buf, parsedName);

            parseName(additionalPtr, buf, parsedCName);
            record.name = parsedCName;
            record.value = parsedName;
            record.type = "CNAME";
        }
        else if (type == T_PTR)
        {
            std::ostringstream stringStream;

            int labelLength = 0;
            while (additionalPtr[labelLength + offset] != 0)
            {
                int currentLabelLength = additionalPtr[labelLength + offset];
                for (int j = 0; j < currentLabelLength; j++)
                {
                    stringStream << additionalPtr[labelLength + offset + j + 1];
                }
                labelLength += currentLabelLength + 1;
                if (additionalPtr[labelLength + offset] != 0)
                    stringStream << ".";
            }
            record.value = stringStream.str();
            record.type = "PTR";
        }
        else
        {
            record.type = "UNSUPPORTED";
        }

        dnsInfo.additionals.push_back(record);
        additionalPtr += offset + rdlength; // Next answer
    }

    /* ----------------------------------------------------------- END OF ADDITIONAL SECTION ANSWERS PARSING ------------------------------------------------------------- */

    return dnsInfo;
}

void DnsResolver::printAnswer(DNS_INFO info)
{

    std::cout << "DNS HEADER: Authoritative: " << info.aa << ", Recursive: " << info.rd << ", Truncated: " << info.tc
              << std::endl;

    std::cout << "Question section(" << info.qdcount << ")" << std::endl
              << "  ";

    std::cout << info.questionName << ", " << info.type << ", IN" << std::endl;

    std::cout << "Answer section(" << info.ancount << ")" << std::endl;
    for (DNS_REC answer : info.answers)
    {
        if (answer.type != "UNSUPPORTED")
            std::cout << "  " << answer.name << "., " << answer.type << ", IN, " << answer.ttl << ", " << answer.value
                  << std::endl;
        else 
            std::cout << "  UNSUPPORTED DNS RECORD TYPE" << std::endl;
    }
    std::cout << std::endl
              << "Authority section (" << info.nscount << ")" << std::endl;
    for (DNS_REC authority : info.authorities)
    {
        if (authority.type != "UNSUPPORTED")
            std::cout << "  " << authority.name << "., " << authority.type << ", IN, " << authority.ttl << ", " << authority.value
                  << std::endl;
        else 
            std::cout << "  UNSUPPORTED DNS RECORD TYPE" << std::endl;

    }

    std::cout << "Additional section (" << info.arcount << ")" << std::endl;

    for (DNS_REC additional : info.additionals)
    {
        if (additional.type != "UNSUPPORTED")
            std::cout << "  " << additional.name << "., " << additional.type << ", IN, " << additional.ttl << ", "
                      << additional.value << std::endl;
        else
            std::cout << "  UNSUPPORTED DNS RECORD TYPE" << std::endl;
    }
}
