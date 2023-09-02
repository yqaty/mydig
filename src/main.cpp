#include <bits/stdc++.h>

#include "../include/CLI11.hpp"
#include "../include/dns.h"
#include "../include/socket.h"
#include "dns.cpp"
#include "socket.cpp"

int main(int argc, char **argv) {
  printf("; <<>> MYDIG <<>>");
  for (int i = 1; i < argc; ++i) {
    printf(" %s", argv[i]);
  }
  puts("");

  std::map<std::string, uint16_t> dns_type;

  dns_type[std::string("A")] = 1;

  dns_type[std::string("NS")] = 2;

  CLI::App app{"mydig"};

  std::string domain_name;
  app.add_option("-d,--domain", domain_name, "query domain name")->required();

  std::string server_name("127.0.0.53");
  app.add_option("-s,--server", server_name, "specify domain name server");

  std::string type("A");
  app.add_option("-t,--type", type, "specify record type");

  bool trace{false};
  app.add_flag("--trace", trace, "Trace delegation down from root");

  CLI11_PARSE(app, argc, argv);
  if (!trace) {
    query(domain_name, server_name, dns_type[type]);
  } else {
    query_trace(domain_name, server_name, dns_type[type]);
  }
  return 0;
}