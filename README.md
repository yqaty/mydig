# mydig

It's a very simple DNS query command like ```dig``` that uses [CLI11](https://github.com/CLIUtils/CLI11) library.

## USAGE

```
Usage: mydig [OPTIONS]

Options:
  -h,--help                   Print this help message and exit
  -d,--domain TEXT REQUIRED   query domain name
  -s,--server TEXT            specify domain name server
  -t,--type TEXT              specify record type
  --trace                     Trace delegation down from root
```
## BUILD

```shell
$ mkdir build
$ cd build
$ cmake ..
$ sudo make && make install
```

``` make install ``` will copy binary file "mydig" to ``` /usr/local/bin ```.

---

## Projects Logs

### Day1 Day2

摸鱼 + 查资料，对着 wireshark 抓的包看了看格式。

感觉不错的文章:

- [DNS 原理入门 - 阮一峰的网络日志](https://www.ruanyifeng.com/blog/2016/06/dns.html)
- [DNS 查询原理详解 - 阮一峰的网络日志](https://www.ruanyifeng.com/blog/2022/08/dns-query.html)

阮一峰 yyds！

### Day3

vscode 甚至今天才装了 C++ 插件。。。。
照着 [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) 把各个类的定义构造写了下。

### Day4

正式开始写各个函数。

学了下 socket 编程，几个要点。

- 网络字节序（大端序）和本机字节序的转化。
- 序列化和反序列化。有 STL容器的类通常内存不连续不能直接 copy。
- UDP 协议传输大致流程：建立套接字，绑定端口，发送/接受信息，关闭套接字。

主要是把 DNS 报文的生成解析写了， 但完全没测试过。

### Day5

把之前写的调试了下，总算能跑了，但只有最基本的查域名。

### Day6

找了个顺眼的 CLI 库 [CLI11](https://github.com/CLIUtils/CLI11)。

把各个功能都完善了一下。

- 支持命令行。
- 支持选定 DNS 服务器。
- 支持查询 NS 记录。
- 支持迭代查询。

basic 部分基本完成了。


### DNS 报文注意事项

- 报文的域名可能被压缩，使用指针，标志是指针的最高的两位是 11, 后面 14 位的值为偏移量。
- 关于顶级域名的 A 记录。直接 ``` dig A com ``` 的响应报文没有 com 的 A 记录，嘻嘻，什么都不会给哦～ ```dig A com +trace``` 只会给一堆 SOA 记录。当然可以先查 NS 记录，再查得到的域名就能获得 A 记录。如果指定某个根服务器询问顶级域名的 A 记录，得到的也只有 SOA 记录。但是！指定根服务器查顶级域名的 ns 记录时，它的 additional 部分会给顶级域名的 A 记录！真神必。
- ```+trace``` 有时候可以一级一级查，但常用的网站通常问根服务器就会有结果，光速跳级。
