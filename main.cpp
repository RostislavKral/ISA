/*
 * ISA DNS Resolver 2023
 * Author: Rostislav Král, xkralr06@vutbr.cz
 * */

#include "dns-resolver.h"

void printHelp()
{
                std::cout << "Usage: " << "./dns [-r] [-x] [-6] -s server [-p port] address" << std::endl
                      << "Options:" << std::endl
                      << "  -r      Recursion desired" << std::endl
                      << "  -x      Reverse query, adress must be IP address!" << std::endl
                      << "  -6      IPv6(AAAA type) DNS query, address must be IPv6" << std::endl
                      << "  -s      Server IP or domain name" << std::endl
                      << "  -p      Port number, default 53" << std::endl
                      << "  -h      Show help" << std::endl << std::endl;
}

int main(int argc, char *argv[])
{
    int c;

    Args args;

    // Processing arguments obtained from the terminal
    while ((c = getopt(argc, argv, "hrx6s:p:")) != -1)
    {
        switch (c)
        {
        case 'h':
            printHelp();
            return 0;
        case 'r':
            args.recursion = true;
            break;
        case 'x':
            args.reverse = true;
            break;
        case '6':
            args.use_ipv6 = true;
            break;
        case 's':
            args.server = optarg;
            break;
        case 'p':
            args.port = std::atoi(optarg);
            break;
        case '?':
            if (optopt == 's' || optopt == 'p')
            {
                printHelp();
                std::cerr << "Parameter -" << static_cast<char>(optopt) << " requires argument." << std::endl;

            }
            else
            {
                printHelp();
                std::cerr << "Unknown parameter -" << static_cast<char>(optopt) << std::endl;
            }
            return 1;
        default:
            printHelp();

            abort();
        }
    }

    if (args.reverse == true && args.use_ipv6 == true)
    {
        printHelp();
        std::cerr << "Invalid combination, can't use -x and -6 together" << std::endl;
        return 1;
    }
    // Checking the address
    if (optind >= argc)
    {
        printHelp();
        std::cerr << "Missing the address argument" << std::endl;
        return 1;
    }

    if (argc < 4 || argc > 8)
    {
        printHelp();
        std::cerr << "Invalid number of arguments" << std::endl;
        exit(1);
    }

    args.domain = argv[optind];

    DnsResolver dnsResolver(args);

    dnsResolver.connectToDNSServer();
    dnsResolver.query();
    dnsResolver.printData();
    DNS_INFO info = dnsResolver.getAnswer();
    dnsResolver.printAnswer(info);

    return 0;
}
