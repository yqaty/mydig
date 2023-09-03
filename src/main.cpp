#include <cstdint>
#include <map>
#include <string>

#include "../include/CLI11.hpp"
#include "../include/socket.hpp"

int main(int argc, char **argv) {
  printf("; <<>> MYDIG <<>>");
  for (int i = 1; i < argc; ++i) {
    printf(" %s", argv[i]);
  }
  puts("");

  std::map<std::string, uint16_t> dns_type;

  dns_type[std::string("A")] = 1;

  dns_type[std::string("a")] = 1;

  dns_type[std::string("NS")] = 2;

  dns_type[std::string("ns")] = 2;

  CLI::App app{"mydig"};

  std::string domain_name;
  app.add_option("-d,--domain", domain_name, "query domain name");

  std::string server_name("127.0.0.53");
  app.add_option("-s,--server", server_name, "specify domain name server");

  std::string type("A");
  app.add_option("-t,--type", type, "specify record type");

  std::string ip_addr;
  app.add_option("-x", ip_addr, "shortcut for reverse lookups");

  bool trace{false};
  app.add_flag("--trace", trace, "Trace delegation down from root");

  CLI11_PARSE(app, argc, argv);
  if (ip_addr.size()) {
    ip_addr = ip_reverse(ip_addr);
    query(ip_addr, server_name, 12);
  } else if (!trace) {
    query(domain_name, server_name, dns_type[type]);
  } else {
    query_trace(domain_name, server_name, dns_type[type]);
  }
  return 0;
}