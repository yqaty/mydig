#ifndef DNS_H
#define DNS_H

#include <iostream>
#include <vector>
class DnsFlags {
 public:
  uint16_t flags;

  DnsFlags(uint16_t qr = 0, uint16_t opcode = 0, uint16_t aa = 0,
           uint16_t tc = 0, uint16_t rd = 0, uint16_t ra = 0, uint16_t z = 0,
           uint16_t rcode = 0);
  uint16_t get_qr();
  uint16_t get_opcode();
  uint16_t get_aa();
  uint16_t get_tc();
  uint16_t get_rd();
  uint16_t get_ra();
  uint16_t get_z();
  uint16_t get_rcode();
  bool check();
  DnsFlags hton();
  DnsFlags ntoh();
  void serialize(std::ostream &os);
};

class DnsHeader {
 public:
  uint16_t id;
  DnsFlags flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;

  DnsHeader(uint16_t id = 0, const DnsFlags &flags = DnsFlags(),
            uint16_t qd_count = 0, uint16_t an_count = 0, uint16_t ns_count = 0,
            uint16_t ar_count = 0);

  DnsHeader hton();
  DnsHeader ntoh();
  void serialize(std::ostream &os);
  void print();
};

class DnsQSF {
 public:
  std::string name;
  uint16_t type;
  uint16_t class_;

  DnsQSF(const std::string &name = "", uint16_t type = 0, uint16_t class_ = 0);
  DnsQSF hton();
  DnsQSF ntoh();
  DnsQSF parse(const std::string &s, int &len);
  void serialize(std::ostream &os);
  void print();
};

class DnsRRF {
 public:
  std::string name;
  uint16_t type;
  uint16_t class_;
  uint32_t ttl;
  uint16_t rdlength;
  std::string rdata;

  DnsRRF(const std::string &name = "", uint16_t type = 0, uint16_t class_ = 0,
         uint32_t ttl = 0, uint16_t rdlength = 0,
         const std::string &rdata = "");

  DnsRRF hton();
  DnsRRF ntoh();
  DnsRRF parse(const std::string &s, int &len);
  void serialize(std::ostream &os);
  void print();
};

class DnsMessage {
 public:
  DnsHeader header;
  std::vector<DnsQSF> question;
  std::vector<DnsRRF> answer;
  std::vector<DnsRRF> authority;
  std::vector<DnsRRF> additional;

  DnsMessage(const DnsHeader &header = DnsHeader());
  DnsMessage hton();
  DnsMessage ntoh();
  void add_question(const std::string domain_name, uint16_t type,
                    uint16_t class_);
  void serialize(std::ostream &os);
  void parse(const std::string &s);
  void gen(const std::string &domain_name, uint16_t query_type, uint16_t RD);
  std::string get_next_ip();
  void print();
};
#endif