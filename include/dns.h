#ifndef DNS_H
#define DNS_H
#include <netinet/in.h>

#include <vector>
class DnsFlags {
 public:
  u_int16_t flags;

  DnsFlags(u_int16_t qr = 0, u_int16_t opcode = 0, u_int16_t aa = 0,
           u_int16_t tc = 0, u_int16_t rd = 0, u_int16_t ra = 0,
           u_int16_t z = 0, u_int16_t rcode = 0);
  u_int16_t get_qr();
  u_int16_t get_opcode();
  u_int16_t get_aa();
  u_int16_t get_tc();
  u_int16_t get_rd();
  u_int16_t get_ra();
  u_int16_t get_z();
  u_int16_t get_rcode();
  bool check();
  DnsFlags hton();
  DnsFlags ntoh();
  void serialize(std::ostream &os);
};

class DnsHeader {
 public:
  u_int16_t id;
  DnsFlags flags;
  u_int16_t qd_count;
  u_int16_t an_count;
  u_int16_t ns_count;
  u_int16_t ar_count;

  DnsHeader(u_int16_t id = 0, const DnsFlags &flags = DnsFlags(),
            u_int16_t qd_count = 0, u_int16_t an_count = 0,
            u_int16_t ns_count = 0, u_int16_t ar_count = 0);

  DnsHeader hton();
  DnsHeader ntoh();
  void serialize(std::ostream &os);
  void print();
};

class DnsQSF {
 public:
  std::string name;
  u_int16_t type;
  u_int16_t class_;

  DnsQSF(const std::string &name = "", u_int16_t type = 0,
         u_int16_t class_ = 0);
  DnsQSF hton();
  DnsQSF ntoh();
  DnsQSF parse(const std::string &s, int &len);
  void serialize(std::ostream &os);
  void print();
};

class DnsRRF {
 public:
  std::string name;
  u_int16_t type;
  u_int16_t class_;
  uint32_t ttl;
  u_int16_t rdlength;
  std::string rdata;

  DnsRRF(const std::string &name = "", u_int16_t type = 0, u_int16_t class_ = 0,
         uint32_t ttl = 0, u_int16_t rdlength = 0,
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
  void add_question(const std::string domain_name, u_int16_t type,
                    u_int16_t class_);
  void serialize(std::ostream &os);
  void parse(const std::string &s);
  void print();
};
#endif