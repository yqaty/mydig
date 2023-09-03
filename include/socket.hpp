#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>

#include <cstdint>

#include "dns.hpp"

class MyAddr {
 public:
  sa_family_t sin_family; /* 地址簇 */
  uint16_t sin_port;      /* 端口 ，要用网络字节序表示*/
  uint32_t sin_addr;
  u_char sin_zero[8];
  MyAddr(sa_family_t sin_family = 0, uint16_t sin_port = 0,
         uint32_t sin_addr = 0);
};

uint32_t A2addr_in(const std::string &s);

void scan(char *buffer);

void send(int sockfd, MyAddr &server_addr, DnsMessage message);

DnsMessage receive(int sockfd, MyAddr &server_addr);

void receive2(int sockfd, MyAddr &server_addr);

void query(std::string domain_name, std::string server, uint16_t query_type);

void query_trace(std::string &domain_name, std::string &server,
                 uint16_t query_type);

std::string ip_reverse(std::string &ip_addr);

#endif