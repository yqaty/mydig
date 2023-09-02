#include <bits/stdc++.h>

#include "../include/CLI11.hpp"
#include "../include/dns.h"
#include "../include/socket.h"
#include "dns.cpp"
#include "socket.cpp"

int main(int argc, char **argv) {
  CLI::App app{"mydig"};

  std::string domain_name;
  app.add_option("-d", domain_name, "query domain name")->required();

  std::string server_name;
  app.add_option("-s", server_name, "specify domain name server");

  CLI11_PARSE(app, argc, argv);

  query(domain_name, server_name);

  return 0;
}