#include "../include/dns.hpp"

#include <netinet/in.h>

#include <cstdint>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "../include/serialization.hpp"

std::string char2byte(char c) {
  uint16_t fi = static_cast<uint16_t>(c >> 4);
  uint16_t se = static_cast<uint16_t>(c & 15);
  std::string s;
  s += fi < 10 ? static_cast<char>(fi + '0') : static_cast<char>(fi - 10 + 'a');
  s += se < 10 ? static_cast<char>(se + '0') : static_cast<char>(se - 10 + 'a');
  return s;
}

uint16_t get_transaction_id() {
  std::random_device rd;
  std::mt19937 gen(rd());

  std::uniform_int_distribution<uint16_t> dist(0, 65535);
  return dist(gen);
}

template <typename T>
void my_deserialize(const std::string &s, int &pos, T &u) {
  std::istringstream is(s.substr(pos, sizeof(T)));
  pos += sizeof(T);
  Deserialize(is, u);
}

std::string dns2n(const std::string &s) {
  if (!s[0]) {
    return s;
  }
  std::string t;
  int last = -1;
  for (int i = 0; i < s.length(); ++i) {
    if (s[i] == '.') {
      t += static_cast<char>(i - last - 1);
      t += s.substr(last + 1, i - last - 1);
      last = i;
    }
  }
  if (last < static_cast<int>(s.length())) {
    t += static_cast<char>(static_cast<int>(s.length()) - last - 1);
    t += s.substr(last + 1, static_cast<int>(s.length()) - last - 1);
  }
  t += static_cast<char>(static_cast<int>(0));
  return t;
}

std::string n2dns(const std::string &s, int &pos) {
  if ((s[pos] & 192) == 192) {
    uint16_t _pos;
    my_deserialize(s, pos, _pos);
    _pos = ntohs(_pos) - 192 * 256;
    int __pos = static_cast<int>(_pos);
    return n2dns(s, __pos);
  } else {
    std::string t;
    int len = static_cast<int>(s[pos]);
    if (len == 0) {
      ++pos;
      return std::string();
    }
    t += s.substr(pos + 1, len) + ".";
    pos += len + 1;
    return t + n2dns(s, pos);
  }
}

// DnsFlags's functions

DnsFlags::DnsFlags(uint16_t qr, uint16_t opcode, uint16_t aa, uint16_t tc,
                   uint16_t rd, uint16_t ra, uint16_t z, uint16_t rcode) {
  flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) |
          (ra << 7) | (z << 4) | (rcode << 0);
}

uint16_t DnsFlags::get_qr() { return flags >> 15 & 1; }

uint16_t DnsFlags::get_opcode() { return flags >> 11 & 15; }

uint16_t DnsFlags::get_aa() { return flags >> 10 & 1; }

uint16_t DnsFlags::get_tc() { return flags >> 9 & 1; }

uint16_t DnsFlags::get_rd() { return flags >> 8 & 1; }

uint16_t DnsFlags::get_ra() { return flags >> 7 & 1; }

uint16_t DnsFlags::get_z() { return flags >> 4 & 7; }

uint16_t DnsFlags::get_rcode() { return flags >> 0 & 15; }

bool DnsFlags::check() {
  uint16_t qr = get_qr();
  uint16_t opcode = get_opcode();
  uint16_t aa = get_aa();
  uint16_t tc = get_tc();
  uint16_t rd = get_rd();
  uint16_t ra = get_ra();
  uint16_t z = get_z();
  uint16_t rcode = get_rcode();
  if (qr == 0) {
    if (opcode > 2 || aa == 1 || tc == 1 || ra == 1 || z || rcode) {
      return 0;
    }
  } else {
    if (opcode >= 3 || z || rcode > 5) return 0;
  }
  return 1;
}

DnsFlags DnsFlags::hton() {
  DnsFlags dns_flags;
  dns_flags.flags = htons(this->flags);
  return dns_flags;
}

DnsFlags DnsFlags::ntoh() {
  DnsFlags dns_flags;
  dns_flags.flags = ntohs(this->flags);
  return dns_flags;
}

void DnsFlags::serialize(std::ostream &os) { Serialize(os, *this); }

// DnsHeader's functions

DnsHeader::DnsHeader(uint16_t id, const DnsFlags &flags, uint16_t qd_count,
                     uint16_t an_count, uint16_t ns_count, uint16_t ar_count) {
  this->id = id;
  this->flags = flags;
  this->qd_count = qd_count;
  this->an_count = an_count;
  this->ns_count = ns_count;
  this->ar_count = ar_count;
}

DnsHeader DnsHeader::hton() {
  return DnsHeader(htons(this->id), this->flags.hton(), htons(this->qd_count),
                   htons(this->an_count), htons(this->ns_count),
                   htons(this->ar_count));
}

DnsHeader DnsHeader::ntoh() {
  return DnsHeader(ntohs(this->id), this->flags.ntoh(), ntohs(this->qd_count),
                   ntohs(this->an_count), ntohs(this->ns_count),
                   ntohs(this->ar_count));
}

void DnsHeader::serialize(std::ostream &os) {
  Serialize(os, id);
  flags.serialize(os);
  Serialize(os, qd_count);
  Serialize(os, an_count);
  Serialize(os, ns_count);
  Serialize(os, ar_count);
}

void DnsHeader::print() {
  printf("%d %d %d %d %d %d\n", this->id, this->flags.flags, this->qd_count,
         this->an_count, this->ns_count, this->ar_count);
}

// DnsQSF's functions

DnsQSF::DnsQSF(const std::string &name, uint16_t type, uint16_t class_) {
  this->name = name;
  this->type = type;
  this->class_ = class_;
}

DnsQSF DnsQSF::hton() {
  return DnsQSF(dns2n(this->name), htons(this->type), htons(this->class_));
}

DnsQSF DnsQSF::ntoh() {
  return DnsQSF(this->name, ntohs(this->type), ntohs(this->class_));
}

DnsQSF DnsQSF::parse(const std::string &s, int &pos) {
  std::string name = n2dns(s, pos);
  uint16_t type;
  uint16_t class_;
  my_deserialize(s, pos, type);
  my_deserialize(s, pos, class_);
  puts("");
  return DnsQSF(name, type, class_).ntoh();
}

void DnsQSF::serialize(std::ostream &os) {
  Serialize(os, this->name);
  Serialize(os, this->type);
  Serialize(os, this->class_);
}

void DnsQSF::print() {
  printf("%s\t\tIN\t %s\n", this->name.c_str(), this->type == 1 ? "A" : "NS");
}

// DnsRRF's functions

DnsRRF::DnsRRF(const std::string &name, uint16_t type, uint16_t class_,
               uint32_t ttl, uint16_t rdlength, const std::string &rdata) {
  this->name = name;
  this->type = type;
  this->class_ = class_;
  this->ttl = ttl;
  this->rdlength = rdlength;
  this->rdata = rdata;
}

DnsRRF DnsRRF::hton() {
  return DnsRRF(dns2n(this->name), htons(this->type), htons(this->class_),
                htonl(this->ttl), htons(this->rdlength), this->rdata);
}

DnsRRF DnsRRF::ntoh() {
  return DnsRRF(this->name, ntohs(this->type), ntohs(this->class_),
                ntohl(this->ttl), ntohs(this->rdlength), this->rdata);
}

DnsRRF DnsRRF::parse(const std::string &s, int &pos) {
  std::string name = n2dns(s, pos);
  uint16_t type;
  uint16_t class_;
  u_int32_t ttl;
  uint16_t rdlength;
  my_deserialize(s, pos, type);
  my_deserialize(s, pos, class_);
  my_deserialize(s, pos, ttl);
  my_deserialize(s, pos, rdlength);
  type = ntohs(type);
  class_ = ntohs(class_);
  ttl = ntohl(ttl);
  rdlength = ntohs(rdlength);
  std::string rdata;
  if (type == 5 || type == 2) {
    rdata = n2dns(s, pos);
  } else {
    rdata.resize(rdlength);
    std::istringstream is(s.substr(pos, rdlength));
    pos += rdlength;
    Deserialize(is, rdata);
  }
  return DnsRRF(name, type, class_, ttl, rdlength, rdata);
}

void DnsRRF::serialize(std::ostream &os) {
  Serialize(os, this->name);
  Serialize(os, this->type);
  Serialize(os, this->class_);
  Serialize(os, this->rdlength);
  Serialize(os, this->rdata);
}

void DnsRRF::print() {
  switch (type) {
    case 1:
      printf("%s\t%u\tIN\tA\t%u.%u.%u.%u\n", name.c_str(), ttl,
             static_cast<uint8_t>(rdata[0]), static_cast<uint8_t>(rdata[1]),
             static_cast<uint8_t>(rdata[2]), static_cast<uint8_t>(rdata[3]));
      break;

    case 2:
      printf("%s\t%u\tIN\tNS\t%s\n", name.c_str(), ttl, rdata.c_str());
      break;

    case 5:
      printf("%s\t%u\tIN\tCNAME\t%s\n", name.c_str(), ttl, rdata.c_str());
      break;

    case 15:
      printf("%s\t%u\tIN\tMX\t%s\n", name.c_str(), ttl, rdata.c_str());
      break;

    case 28: {
      std::string s;
      for (int i = 0; i < rdata.size(); ++i) {
        s += char2byte(rdata[i]);
        if ((i & 1) && i + 1 < rdata.size()) {
          s += ':';
        }
      }
      printf("%s\t%u\tIN\tAAAA\t%s\n", name.c_str(), ttl, s.c_str());
      break;
    }

    default:
      break;
  }
}

// DnsMessage's functions

DnsMessage::DnsMessage(const DnsHeader &header) {
  this->header = header;
  this->question.resize(header.qd_count);
  this->answer.resize(header.an_count);
  this->authority.resize(header.ns_count);
  this->additional.resize(header.ar_count);
}

DnsMessage DnsMessage::hton() {
  DnsMessage message(this->header);
  message.header = message.header.hton();
  int pos = 0;
  for (auto &u : this->question) {
    message.question[pos++] = u.hton();
  }
  pos = 0;
  for (auto &u : this->answer) {
    message.answer[pos++] = u.hton();
  }
  pos = 0;
  for (auto &u : this->authority) {
    message.authority[pos++] = u.hton();
  }
  pos = 0;
  for (auto &u : this->additional) {
    message.additional[pos++] = u.hton();
  }
  return message;
}

DnsMessage DnsMessage::ntoh() {
  DnsMessage message(this->header);
  message.header = message.header.ntoh();
  int pos = 0;
  for (auto &u : this->question) {
    message.question[pos++] = u.ntoh();
  }
  pos = 0;
  for (auto &u : this->answer) {
    message.answer[pos++] = u.ntoh();
  }
  pos = 0;
  for (auto &u : this->authority) {
    message.authority[pos++] = u.ntoh();
  }
  pos = 0;
  for (auto &u : this->additional) {
    message.additional[pos++] = u.ntoh();
  }
  return message;
}

void DnsMessage::add_question(const std::string domain_name, uint16_t type,
                              uint16_t class_) {
  this->header.qd_count++;
  this->question.push_back(DnsQSF(domain_name, type, class_));
}

void DnsMessage::serialize(std::ostream &os) {
  this->header.serialize(os);
  for (auto &u : this->question) {
    u.serialize(os);
  }
  for (auto &u : this->answer) {
    u.serialize(os);
  }
  for (auto &u : this->authority) {
    u.serialize(os);
  }
  for (auto &u : this->additional) {
    u.serialize(os);
  }
}

void DnsMessage::parse(const std::string &s) {
  DnsHeader header;
  std::istringstream is(s.substr(0, 12));
  Deserialize(is, header);
  header = header.ntoh();
  DnsMessage message(header);
  int pos = 12;
  for (auto &u : message.question) {
    u = u.parse(s, pos);
  }
  for (auto &u : message.answer) {
    u = u.parse(s, pos);
  }
  for (auto &u : message.authority) {
    u = u.parse(s, pos);
  }
  for (auto &u : message.additional) {
    u = u.parse(s, pos);
  }
  *this = message;
}

void DnsMessage::gen(const std::string &domain_name, uint16_t query_type,
                     uint16_t RD) {
  uint16_t transaction_id = get_transaction_id();
  DnsMessage message(
      DnsHeader(transaction_id, DnsFlags(0, 0, 0, 0, RD, 0, 0, 0), 0, 0, 0, 0));
  message.add_question(domain_name, query_type, 1);
  *this = message;
}

std::string DnsMessage::get_next_ip() {
  for (auto &u : additional) {
    if (u.type == 1) return u.rdata;
  }
  return std::string();
}

void DnsMessage::print() {
  printf(";; global options: +cmd\n");
  printf(";; Got answer\n");
  printf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: %u\n", header.id);
  printf(";; flags: ");
  if (header.flags.get_qr() == 1) {
    printf("qr ");
  }
  if (header.flags.get_aa()) {
    printf("aa ");
  }
  if (header.flags.get_tc()) {
    printf("tc ");
  }
  if (header.flags.get_rd()) {
    printf("rd ");
  }
  if (header.flags.get_ra()) {
    printf("ra ");
  }
  printf("; QUERY: %u, ANSWER: %u, AUTHORITY: %u, ADDITIONAL: %u\n\n",
         header.qd_count, header.an_count, header.ns_count, header.ar_count);
  if (question.size()) {
    printf(";; QUESTION SECTION:\n");
    for (auto &u : question) {
      u.print();
    }
    puts("");
  }
  if (answer.size()) {
    printf(";; ANSWER SECTION:\n");
    for (auto &u : answer) {
      u.print();
    }
    puts("");
  }
  if (authority.size()) {
    printf(";; AUTHORITY SECTION:\n");
    for (auto &u : authority) {
      u.print();
    }
    puts("");
  }
  if (additional.size()) {
    printf(";; ADDITIONAL SECTION:\n");
    for (auto &u : additional) {
      u.print();
    }
    puts("");
  }
}