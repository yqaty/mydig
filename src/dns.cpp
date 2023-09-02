#include "../include/dns.h"

#include <bits/stdc++.h>

#include "../include/serialization.h"

template <typename T>
void my_deserialize(const std::string &s, int &pos, T &u) {
  std::istringstream is(s.substr(pos, sizeof(T)));
  pos += sizeof(T);
  deserialize(is, u);
}

std::string dns2n(const std::string &s) {
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
    u_int16_t _pos;
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

DnsFlags::DnsFlags(u_int16_t qr, u_int16_t opcode, u_int16_t aa, u_int16_t tc,
                   u_int16_t rd, u_int16_t ra, u_int16_t z, u_int16_t rcode) {
  flags = (qr << 15) | (opcode << 11) | (aa << 10) | (tc << 9) | (rd << 8) |
          (ra << 7) | (z << 4) | (rcode << 0);
}

u_int16_t DnsFlags::get_qr() { return flags >> 15 & 1; }

u_int16_t DnsFlags::get_opcode() { return flags >> 11 & 15; }

u_int16_t DnsFlags::get_aa() { return flags >> 10 & 1; }

u_int16_t DnsFlags::get_tc() { return flags >> 9 & 1; }

u_int16_t DnsFlags::get_rd() { return flags >> 8 & 1; }

u_int16_t DnsFlags::get_ra() { return flags >> 7 & 1; }

u_int16_t DnsFlags::get_z() { return flags >> 4 & 7; }

u_int16_t DnsFlags::get_rcode() { return flags >> 0 & 15; }

bool DnsFlags::check() {
  u_int16_t qr = get_qr();
  u_int16_t opcode = get_opcode();
  u_int16_t aa = get_aa();
  u_int16_t tc = get_tc();
  u_int16_t rd = get_rd();
  u_int16_t ra = get_ra();
  u_int16_t z = get_z();
  u_int16_t rcode = get_rcode();
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

void DnsFlags::serialize(std::ostream &os) {
  serialize_for_copyable(os, *this);
}

// DnsHeader's functions

DnsHeader::DnsHeader(u_int16_t id, const DnsFlags &flags, u_int16_t qd_count,
                     u_int16_t an_count, u_int16_t ns_count,
                     u_int16_t ar_count) {
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
  serialize_for_copyable(os, *this);
}

void DnsHeader::print() {
  printf("%d %d %d %d %d %d\n", this->id, this->flags.flags, this->qd_count,
         this->an_count, this->ns_count, this->ar_count);
}

// DnsQSF's functions

DnsQSF::DnsQSF(const std::string &name, u_int16_t type, u_int16_t class_) {
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
  u_int16_t type;
  uint16_t class_;
  my_deserialize(s, pos, type);
  my_deserialize(s, pos, class_);
  puts("");
  return DnsQSF(name, type, class_).ntoh();
}

void DnsQSF::serialize(std::ostream &os) {
  serialize_for_STL(os, this->name);
  serialize_for_copyable(os, this->type);
  serialize_for_copyable(os, this->class_);
}

void DnsQSF::print() { printf("%s\t\tIN\t A", this->name.c_str()); }

// DnsRRF's functions

DnsRRF::DnsRRF(const std::string &name, u_int16_t type, u_int16_t class_,
               uint32_t ttl, u_int16_t rdlength, const std::string &rdata) {
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
  u_int16_t type;
  u_int16_t class_;
  u_int32_t ttl;
  u_int16_t rdlength;
  my_deserialize(s, pos, type);
  my_deserialize(s, pos, class_);
  my_deserialize(s, pos, ttl);
  my_deserialize(s, pos, rdlength);
  type = ntohs(type);
  class_ = ntohs(class_);
  ttl = ntohl(ttl);
  rdlength = ntohs(rdlength);
  std::string rdata;
  if (type == 5) {
    rdata = n2dns(s, pos);
  } else {
    rdata.resize(rdlength);
    std::istringstream is(s.substr(pos, rdlength));
    pos += rdlength;
    deserialize(is, rdata);
  }
  return DnsRRF(name, type, class_, ttl, rdlength, rdata);
}

void DnsRRF::serialize(std::ostream &os) {
  serialize_for_STL(os, this->name);
  serialize_for_copyable(os, this->type);
  serialize_for_copyable(os, this->class_);
  serialize_for_copyable(os, this->rdlength);
  serialize_for_STL(os, this->rdata);
}

void DnsRRF::print() {
  if (type == 1) {
    printf("%s\t%u\tIN\tA\t%u.%u.%u.%u\n", name.c_str(), ttl,
           static_cast<uint8_t>(rdata[0]), static_cast<uint8_t>(rdata[1]),
           static_cast<uint8_t>(rdata[2]), static_cast<uint8_t>(rdata[3]));
  } else if (type == 5) {
    printf("%s\t%u\tIN\tCNAME\t%s\n", name.c_str(), ttl, rdata.c_str());
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

void DnsMessage::add_question(const std::string domain_name, u_int16_t type,
                              u_int16_t class_) {
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
  deserialize(is, header);
  header = header.ntoh();
  DnsMessage message(header);
  int pos = 12;
  ////std::cout << pos << std::endl;
  for (int i = 12; i < 30; ++i) {
    ////std::cout << (int)s[i] << " ";
  }
  ////std::cout << '\n';
  for (auto &u : message.question) {
    u = u.parse(s, pos);
  }
  ////std::cout << "answer" << pos << std::endl;
  for (auto &u : message.answer) {
    ////std::cout << "+1:" << pos << std::endl;
    u = u.parse(s, pos);
  }
  ////std::cout << "authority" << pos << std::endl;
  for (auto &u : message.authority) {
    u = u.parse(s, pos);
  }
  ////std::cout << "additional" << pos << std::endl;
  for (auto &u : message.additional) {
    u = u.parse(s, pos);
  }
  *this = message;
}

void DnsMessage::print() {
  printf("; <<>> MYDIG <<>> %s\n", question[0].name.c_str());
  printf(";; global options: +cmd\n");
  if (answer.size()) {
    printf(";; Got answer\n");
  } else {
    printf(";; No answer\n");
  }
  printf(";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: u\n", header.id);
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