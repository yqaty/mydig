#include "../include/socket.h"

#include <arpa/inet.h>
#include <bits/stdc++.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "../include/dns.h"
#include "../include/serialization.h"

const u_int16_t SENDPORT = 9090;
const u_int16_t DNSPORT = 53;
const int UDPMAXSIZE = 512;

MyAddr::MyAddr(sa_family_t sin_family, u_int16_t sin_port, uint32_t sin_addr) {
  this->sin_family = sin_family;
  this->sin_port = sin_port;
  this->sin_addr = sin_addr;
  memset(this->sin_zero, 0, sizeof(this->sin_zero));
}

void scan(char *buffer) {
  int size;
  std::cin >> size;
  for (int i = 0; i < size; ++i) {
    scanf("%s", buffer + i);
    printf("%s ", buffer + i);
    if (buffer[i] >= '0' && buffer[i] <= '9')
      buffer[i] -= '0';
    else if (buffer[i] >= 'a' && buffer[i] <= 'f')
      buffer[i] -= 'a' - 10;
    if (buffer[i + 1] >= '0' && buffer[i + 1] <= '9')
      buffer[i + 1] -= '0';
    else if (buffer[i + 1] >= 'a' && buffer[i + 1] <= 'f')
      buffer[i + 1] -= 'a' - 10;
    buffer[i] = buffer[i] * 16 + buffer[i + 1];
  }
  puts("");
  for (int i = 0; i < size; ++i) {
    printf("%u ", static_cast<u_int8_t>(buffer[i]));
  }
  puts("");
  buffer[size] = 0;
}

void send(int sockfd, std::string domain_name, MyAddr &server_addr) {
  std::random_device rd;
  std::mt19937 gen(rd());

  // Generate a random transaction ID in the range [0, 65535]
  std::uniform_int_distribution<uint16_t> dist(0, 65535);
  std::ostringstream os;
  u_int16_t transaction_id = dist(gen);
  DnsMessage message = DnsMessage(
      DnsHeader(transaction_id, DnsFlags(0, 0, 0, 0, 1, 0, 0, 0), 0, 0, 0, 0));
  message.add_question(domain_name, 1, 1);
  message = message.hton();
  message.serialize(os);
  std::string sos = os.str();
  sendto(sockfd, reinterpret_cast<void *>(const_cast<char *>(sos.c_str())),
         sos.size(), 0, reinterpret_cast<sockaddr *>(&server_addr),
         sizeof(struct sockaddr));
}

void receive(int sockfd, MyAddr &server_addr) {
  MyAddr addr_from;
  char buffer[2 * UDPMAXSIZE];
  socklen_t fromlen = sizeof(struct sockaddr);
  std::cout << "!!" << std::endl;
  int len = recvfrom(sockfd, buffer, UDPMAXSIZE * 2, 0,
                     reinterpret_cast<sockaddr *>(&addr_from), &fromlen);
  std::string sis;
  sis.resize(len);
  for (int i = 0; i < len; ++i) {
    sis[i] = buffer[i];
  }
  DnsMessage message;
  message.parse(sis);
  message.print();
}

void receive2(int sockfd, MyAddr &server_addr) {
  char buffer[2 * UDPMAXSIZE];
  scan(buffer);
  std::string sis;
  sis.resize(90);
  for (int i = 0; i < 90; ++i) sis[i] = buffer[i];
  puts("");
  DnsMessage message;
  message.parse(sis);
  message.print();
}

void query(std::string domain_name,
           std::string server = std::string("127.0.0.53")) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    std::cerr << "socket() error" << std::endl;
    return;
  }
  MyAddr my_addr(AF_INET, htons(SENDPORT), htonl(INADDR_ANY));
  bind(sockfd, reinterpret_cast<sockaddr *>(&my_addr), sizeof(struct sockaddr));
  MyAddr server_addr(AF_INET, htons(DNSPORT), inet_addr(server.c_str()));
  send(sockfd, domain_name, server_addr);
  receive(sockfd, server_addr);
  // receive2(sockfd, server_addr);
  close(sockfd);
}

/*
90
e5 9f 81 80 00 01 00 03 00 00 00 00 03 77 77 77
05 62 61 69 64 75 03 63 6f 6d 00 00 01 00 01 c0
0c 00 05 00 01 00 00 03 ad 00 0f 03 77 77 77 01
61 06 73 68 69 66 65 6e c0 16 c0 2b 00 01 00 01
00 00 03 ad 00 04 b6 3d c8 07 c0 2b 00 01 00 01
00 00 03 ad 00 04 b6 3d c8 06

Frame 2: 134 bytes on wire (1072 bits), 134 bytes captured (1072 bits) on
interface any, id 0 Linux cooked capture v1 Internet Protocol Version 4, Src:
127.0.0.53, Dst: 127.0.0.1 User Datagram Protocol, Src Port: 53, Dst Port: 9090
Domain Name System (response)
    Transaction ID: 0xe59f
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 3
    Authority RRs: 0
    Additional RRs: 0
    Queries
        www.baidu.com: type A, class IN
            Name: www.baidu.com
            [Name Length: 13]
            [Label Count: 3]
            Type: A (Host Address) (1)
            Class: IN (0x0001)
    Answers
        www.baidu.com: type CNAME, class IN, cname www.a.shifen.com
            Name: www.baidu.com
            Type: CNAME (Canonical NAME for an alias) (5)
            Class: IN (0x0001)
            Time to live: 941 (15 minutes, 41 seconds)
            Data length: 15
            CNAME: www.a.shifen.com
        www.a.shifen.com: type A, class IN, addr 182.61.200.7
            Name: www.a.shifen.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 941 (15 minutes, 41 seconds)
            Data length: 4
            Address: 182.61.200.7
        www.a.shifen.com: type A, class IN, addr 182.61.200.6
            Name: www.a.shifen.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 941 (15 minutes, 41 seconds)
            Data length: 4
            Address: 182.61.200.6
    [Request In: 1]
    [Time: 0.000228741 seconds]

*/
