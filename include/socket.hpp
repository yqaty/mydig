#ifndef SOCKET_H
#define SOCKET_H

#include <bits/stdc++.h>
#include <sys/socket.h>
#include <sys/types.h>

class MyAddr {
 public:
  sa_family_t sin_family; /* 地址簇 */
  uint16_t sin_port;      /* 端口 ，要用网络字节序表示*/
  uint32_t sin_addr;
  u_char sin_zero[8];
  MyAddr(sa_family_t sin_family = 0, uint16_t sin_port = 0,
         uint32_t sin_addr = 0);
};

#endif