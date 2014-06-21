#ifndef FLOW_HPP
#define FLOW_HPP

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/stat.h>
#include <vector>
#include <unordered_map>

enum AGGREGATION{
	ANOAGGREGATION = 0,
	ASRCIP,
	ASRCIP4,
	ASRCIP6,
	ADSTIP,
	ADSTIP4,
	ADSTIP6,
	ASRCPORT,
	ADSTPORT
};

enum SORT{
	SNOSORT = 0,
	SPACKETS,
	SBYTES
};

struct param {
	char * directory;
	AGGREGATION aggregationTypeId; // 1 - src ip4/mask, 2 - src ip6/mask, 3 - des ip4/mask, 4 - des ip4/mask, 5 - src port, 6 - dst port
	char * ipMaskOrPort;
	SORT sortTypeId; // 1 - packets, 2 - bytes 
};

struct flow {
	uint32_t		sa_family;
	struct in6_addr src_addr;
	struct in6_addr dst_addr;
	uint16_t		src_port;
	uint16_t		dst_port;
	uint64_t        packets;
	uint64_t        bytes;
};

struct data {
	std::string ip;
	uint16_t port;
	uint64_t packets;
	uint64_t bytes;
};

void print(void);
void readFile(struct param *, char *, std::vector<struct flow> &);
void readPath(struct param *);
struct param * parseParams(int, char **);
#endif