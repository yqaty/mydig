#include "../include/socket.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <sstream>

#include "../include/dns.hpp"
#include "../include/serialization.hpp"

const uint16_t SENDPORT = 9090;
const uint16_t DNSPORT = 53;
const int UDPMAXSIZE = 512;

MyAddr::MyAddr(sa_family_t sin_family, uint16_t sin_port, uint32_t sin_addr) {
  this->sin_family = sin_family;
  this->sin_port = sin_port;
  this->sin_addr = sin_addr;
  memset(this->sin_zero, 0, sizeof(this->sin_zero));
}

uint32_t A2addr_in(const std::string &s) {
  return (static_cast<uint32_t>(static_cast<uint8_t>(s[0]))) |
         (static_cast<uint32_t>(static_cast<uint8_t>(s[1])) << 8) |
         (static_cast<uint32_t>(static_cast<uint8_t>(s[2])) << 16) |
         (static_cast<uint32_t>(static_cast<uint8_t>(s[3])) << 24);
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

void send(int sockfd, MyAddr &server_addr, DnsMessage message) {
  message = message.hton();
  std::ostringstream os;
  message.serialize(os);
  std::string sos = os.str();
  sendto(sockfd, reinterpret_cast<void *>(const_cast<char *>(sos.c_str())),
         sos.size(), 0, reinterpret_cast<sockaddr *>(&server_addr),
         sizeof(struct sockaddr));
}

DnsMessage receive(int sockfd, MyAddr &server_addr) {
  MyAddr addr_from;
  char buffer[UDPMAXSIZE + 1];
  socklen_t fromlen = sizeof(struct sockaddr);
  int len;
  do {
    len = recvfrom(sockfd, buffer, UDPMAXSIZE, 0,
                   reinterpret_cast<sockaddr *>(&addr_from), &fromlen);
  } while (addr_from.sin_addr != server_addr.sin_addr);
  std::string sis;
  sis.resize(len);
  for (int i = 0; i < len; ++i) {
    sis[i] = buffer[i];
  }
  DnsMessage message;
  message.parse(sis);
  return message;
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

void query(std::string domain_name, std::string server, uint16_t query_type) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    std::cerr << "socket() error" << std::endl;
    return;
  }
  MyAddr my_addr(AF_INET, htons(SENDPORT), htonl(INADDR_ANY));
  bind(sockfd, reinterpret_cast<sockaddr *>(&my_addr), sizeof(struct sockaddr));
  MyAddr server_addr(AF_INET, htons(DNSPORT), inet_addr(server.c_str()));
  DnsMessage message;
  message.gen(domain_name, query_type, 1);
  send(sockfd, server_addr, message);
  message = receive(sockfd, server_addr);
  message.print();
  close(sockfd);
}

void query_trace(std::string &domain_name, std::string &server,
                 uint16_t query_type) {
  int sockfd;
  sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (sockfd == -1) {
    std::cerr << "socket() error" << std::endl;
    return;
  }

  MyAddr my_addr(AF_INET, htons(SENDPORT), htonl(INADDR_ANY));
  bind(sockfd, reinterpret_cast<sockaddr *>(&my_addr), sizeof(struct sockaddr));
  MyAddr server_addr(AF_INET, htons(DNSPORT), inet_addr(server.c_str()));
  DnsMessage message;
  message.gen(std::string(1, static_cast<char>(0)), 2, 1);
  send(sockfd, server_addr, message);
  DnsMessage recvmsg(receive(sockfd, server_addr));
  recvmsg.print();
  recvmsg.answer[0].rdata.erase(recvmsg.answer[0].rdata.size() - 1);
  message.gen(recvmsg.answer[0].rdata, 1, 1);
  send(sockfd, server_addr, message);
  recvmsg = receive(sockfd, server_addr);
  recvmsg.print();
  server = recvmsg.answer[0].rdata;
  while (1) {
    MyAddr server_addr(AF_INET, htons(DNSPORT), A2addr_in(server));
    DnsMessage message;
    message.gen(domain_name, query_type, 1);
    send(sockfd, server_addr, message);
    DnsMessage recvmsg(receive(sockfd, server_addr));
    recvmsg.print();
    if (recvmsg.answer.size()) {
      break;
    }
    server = recvmsg.get_next_ip();
    if (server.size() != 4) {
      break;
    }
  }
  close(sockfd);
}