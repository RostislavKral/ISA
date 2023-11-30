/**
 * @author Rostislav Kral
 * @brief Tests for the project. Some tests can possibly fail (even though the information obtained in real time from the resolver are correct) due to possible inconsistencies of DNS system.
 * @file tests.cpp
 * */

#include "googletest/googletest/include/gtest/gtest.h"
#include "googletest/googlemock/include/gmock/gmock.h"
#include "dns-resolver.h"


TEST(Ipv4ATestSuite, CnameGithubTest)
{
    Args arguments;
    arguments.recursion = true;
    arguments.domain = "www.github.com";
    arguments.server = "8.8.8.8";

    DnsResolver dnsResolver(arguments);

    dnsResolver.connectToDNSServer();
    dnsResolver.query();
    DNS_INFO result = dnsResolver.getAnswer();

ASSERT_EQ(result.ancount, 2);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.answers[0].type, "CNAME");
ASSERT_EQ(result.answers[0].name.substr(0,  result.answers[0].name.size()-1), "www.github.com");
ASSERT_EQ(result.answers[0].value.substr(0,  result.answers[0].value.size()-1), "github.com");

ASSERT_EQ(result.answers[1].type, "A");
ASSERT_EQ(result.answers[1].value, "140.82.121.4");
ASSERT_EQ(result.answers[1].name.substr(0,  result.answers[1].name.size()-1), "github.com");


}

TEST(Ipv4ATestSuite, GithubWithRecursionWithoutWWW)
{
Args arguments;
arguments.recursion = true;
arguments.domain = "github.com";
arguments.server = "8.8.8.8";

DnsResolver dnsResolver(arguments);

dnsResolver.connectToDNSServer();
dnsResolver.query();
DNS_INFO result = dnsResolver.getAnswer();

std::string name = result.answers.front().name;
name = name.substr(0, name.size()-1);

ASSERT_EQ(result.ancount, 1);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.questionName, "github.com.");
ASSERT_EQ(result.answers.front().value, "140.82.121.4");
ASSERT_EQ(result.answers.front().type, "A");
ASSERT_EQ(name, "github.com");
}

TEST(Ipv6AAAATestSuite, IPv6FITVUT)
{
Args arguments;
arguments.recursion = true;
arguments.domain = "fit.vut.cz";
arguments.server = "8.8.8.8";
arguments.use_ipv6 = true;

DnsResolver dnsResolver(arguments);

dnsResolver.connectToDNSServer();
dnsResolver.query();
DNS_INFO result = dnsResolver.getAnswer();

std::string name = result.answers.front().name;
name = name.substr(0, name.size()-1);

ASSERT_EQ(result.ancount, 1);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.questionName, "fit.vut.cz.");
ASSERT_EQ(result.answers.front().value, "2001:67c0:1220:8090:0000:0000:93e5:91a0");
ASSERT_EQ(result.answers.front().type, "AAAA");
ASSERT_EQ(name, "fit.vut.cz");
}



TEST(HelpersSuite, ExplodeString)
{
std::vector<std::string> res = explode("123.12.1.0",'.');

std::vector<std::string> expected = {"123","12","1","0"};

ASSERT_EQ(res, expected);
}

TEST(HelpersSuite, ExplodeEmptyString)
{
std::vector<std::string> res = explode("",'.');

std::vector<std::string> expected = {};

ASSERT_EQ(res, expected);
}

TEST(HelpersSuite, ExplodeStringNonPresentDelimiter)
{
std::vector<std::string> res = explode("123.12.1.0",',');

std::vector<std::string> expected = {"123.12.1.0"};

ASSERT_EQ(res, expected);
}

TEST(PTRBuilderSuite, IPv4)
{
std::string reversedIP = buildPTRQuery("192.0.2.1");

ASSERT_EQ(reversedIP, "1.2.0.192.in-addr.arpa");
}

TEST(PTRBuilderSuite, IPv6)
{
std::string reversedIP = buildPTRQuery("2001:0db8:85a3:0000:0000:8a2e:0370:7334");

ASSERT_EQ(reversedIP, "4.3.3.7.0.7.3.0.e.2.a.8.0.0.0.0.0.0.0.0.3.a.5.8.8.b.d.0.1.0.0.2.ip6.arpa");
}
TEST(PTRBuilderSuite, IPv6Kazi)
{
std::string reversedIP = buildPTRQuery("2001:4860:4860::8888");

ASSERT_EQ(reversedIP, "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2.ip6.arpa");
}

TEST(PTRBuilderSuite, InvalidIPAddressFormat)
{
ASSERT_EXIT({buildPTRQuery("Invalid IP address format test");},
::testing::ExitedWithCode(255),
"Invalid IP address!");
}

TEST(ReverseQuerySuite, VUTFIT)
{
    Args args;
    args.recursion = true;
    args.reverse = true;
    args.server = "8.8.8.8";
    args.domain = "147.229.9.26";

DnsResolver dnsResolver(args);

dnsResolver.connectToDNSServer();
dnsResolver.query();
DNS_INFO result = dnsResolver.getAnswer();


ASSERT_EQ(result.ancount, 1);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.questionName, "26.9.229.147.in-addr.arpa.");
ASSERT_EQ(result.type, "PTR");
ASSERT_EQ(result.answers[0].name.substr(0,  result.answers[0].name.size()-1), "26.9.229.147.in-addr.arpa");
ASSERT_EQ(result.answers.front().value, "www.fit.vut.cz");

}

TEST(ReverseQuerySuite, ReverseIPv6VUTFIT)
{
Args args;
args.recursion = true;
args.reverse = true;
args.server = "8.8.8.8";
args.domain = "2001:67c:1220:809::93e5:91a";

DnsResolver dnsResolver(args);

dnsResolver.connectToDNSServer();
dnsResolver.query();
DNS_INFO result = dnsResolver.getAnswer();


ASSERT_EQ(result.ancount, 1);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.questionName, "a.1.9.0.5.e.3.9.0.0.0.0.0.0.0.0.9.0.8.0.0.2.2.1.c.7.6.0.1.0.0.2.ip6.arpa.");
ASSERT_EQ(result.type, "PTR");
ASSERT_EQ(result.answers[0].name.substr(0,  result.answers[0].name.size()-1), "a.1.9.0.5.e.3.9.0.0.0.0.0.0.0.0.9.0.8.0.0.2.2.1.c.7.6.0.1.0.0.2.ip6.arpa");
ASSERT_EQ(result.answers.front().value, "www.fit.vut.cz");

}

TEST(KaziIPv6ReverseAuthorityAndAdditionalSuite, KaziIPv6)
{
Args args;
args.reverse = true;
args.server = "kazi.fit.vutbr.cz";
args.domain = "2001:4860:4860::8888";

DnsResolver dnsResolver(args);

dnsResolver.connectToDNSServer();
dnsResolver.query();
DNS_INFO result = dnsResolver.getAnswer();

ASSERT_EQ(result.ancount, 0);
ASSERT_EQ(result.qdcount, 1);
ASSERT_EQ(result.nscount, 6);
ASSERT_EQ(result.arcount, 12);


ASSERT_EQ(result.authorities.front().name.substr(0,result.authorities.front().name.size()-1), "ip6.arpa");
ASSERT_EQ(result.authorities.front().type, "NS");
ASSERT_EQ(result.authorities.front().ttl, 172800);
ASSERT_EQ(result.authorities.front().value.substr(0,result.authorities.front().value.size()-1), "e.ip6-servers.arpa");

ASSERT_EQ(result.additionals.front().name.substr(0,result.additionals.front().name.size()-1), "f.ip6-servers.arpa");
ASSERT_EQ(result.additionals.front().type, "AAAA");
ASSERT_EQ(result.additionals.front().ttl, 172800);
ASSERT_EQ(result.additionals.front().value, "2001:67c0:e000:0000:0000:0000:0000:2000");

}

int main()
{
    testing::InitGoogleTest();
    testing::InitGoogleMock();


   return RUN_ALL_TESTS();
}