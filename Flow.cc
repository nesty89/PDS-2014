#include "Flow.hpp"
#include <getopt.h>
#include <string.h>
#include <dirent.h>
#include <vector>
#include <unordered_map>
#include <arpa/inet.h>
#include <algorithm> 

bool sortByBytes(const struct data &x, const struct data &y){
	return x.bytes > y.bytes;
}

bool sortByPackets(const struct data &x, const struct data &y){
	return x.packets > y.packets;
}

void freeAll(struct param *p){
	free(p);
}

void printHelp(void){
	fprintf(stdout, "Napoveda");
	exit(0);
}

struct param* parseParams(int argc, char ** argv){
	if (argc < 7){
		fprintf(stderr, "Chybny pocet parametru\n");
		exit(1);
	}
	// inicializace struktury nesouci parametry
	struct param *params  = (struct param *) malloc(sizeof(struct param));
	if (params == NULL){
		fprintf(stderr, "Chyba pri zpracovani parametru (funkce malloc)\n");
		exit(1);
	}
	// zakladni inicializace struktury
	params->directory = NULL;
	params->ipMaskOrPort = NULL;
	params->aggregationTypeId = ANOAGGREGATION;
	params->sortTypeId = SNOSORT;
	
	int id;
	while((id = getopt(argc, argv, "a:s:f:h")) != -1){
		switch (id){
			case 'f': // directory address
				params->directory = optarg;
			break;
			case 'a': // podle ceho agreguji
				if(((std::string) optarg).find("srcip4") != std::string::npos){
					params->aggregationTypeId = ASRCIP4;
					params->ipMaskOrPort = optarg;
					params->ipMaskOrPort = (char *)(((std::string) params->ipMaskOrPort).erase(0,7)).c_str();
				} else if(((std::string) optarg).find("srcip6") != std::string::npos){
					params->aggregationTypeId = ASRCIP6;
					params->ipMaskOrPort = optarg;
					params->ipMaskOrPort = (char *)(((std::string) params->ipMaskOrPort).erase(0,7)).c_str();
				} else if(((std::string) optarg).find("dstip4") != std::string::npos){
					params->aggregationTypeId = ADSTIP4;
					params->ipMaskOrPort = optarg;
					params->ipMaskOrPort = (char *)(((std::string) params->ipMaskOrPort).erase(0,7)).c_str();
				} else if(((std::string) optarg).find("dstip6") != std::string::npos){
					params->aggregationTypeId = ADSTIP6;
					params->ipMaskOrPort = optarg;
					params->ipMaskOrPort = (char *)(((std::string) params->ipMaskOrPort).erase(0,7)).c_str();
				} else if(((std::string) optarg).find("srcport") != std::string::npos){
					params->aggregationTypeId = ASRCPORT;
					//params->ipMaskOrPort = NULL;
				} else if(((std::string) optarg).find("dstport") != std::string::npos){
					params->aggregationTypeId = ADSTPORT;
					//params->ipMaskOrPort = NULL;
				} else if(((std::string) optarg).find("srcip") != std::string::npos){
					params->aggregationTypeId = ASRCIP;
				//	params->ipMaskOrPort = "";
				} else if(((std::string) optarg).find("dstip") != std::string::npos){
					params->aggregationTypeId = ASRCIP;
				//	params->ipMaskOrPort = "";
				} else {
					freeAll(params);
					fprintf(stderr, "Chyba zadaneho parametru -a\n");
					exit(1);
				}
			break;
			case 's':
			    if(strcmp(optarg, "packets") == 0){
					params->sortTypeId = SPACKETS;					
				} else if(strcmp(optarg, "bytes") == 0){
					params->sortTypeId = SBYTES;					
				} else {
					freeAll(params);
					fprintf(stderr, "Chyba zadaneho parametru -s\n");
					exit(1);
				}
			break;
			case 'h': printHelp(); freeAll(params); exit(0); break; // napoveda
			default: printHelp(); freeAll(params); exit(0); break; // neplatny parametr
		}
	}
	if (params->aggregationTypeId == ANOAGGREGATION || params->sortTypeId == SNOSORT || params->directory == NULL){
					freeAll(params);
					fprintf(stderr, "Chyba vstupnich parametru\n");
					exit(1);
	}
	return params;
}

// nechat probublat ukladaci prostory nebo zavedst navic obsluzne linky?
void parsePacket(struct param* params, struct flow * fl, std::unordered_map<std::string, struct data> &map){

	struct data d;
	std::unordered_map<std::string, struct data>::const_iterator got;
	std::string s;
	char ip[INET6_ADDRSTRLEN];
	std::string str;
	if(params->ipMaskOrPort != NULL){
		str = params->ipMaskOrPort;
	}
	int mask = 0;
	short Mask = 0xFF;
	struct in6_addr tmp;
	
	if(params->ipMaskOrPort != NULL){
		mask = atoi(params->ipMaskOrPort);
	}
	switch(params->aggregationTypeId){
		case ASRCIP:
			inet_ntop(AF_INET6, &(fl->src_addr), ip, INET6_ADDRSTRLEN);
			s = ip;
			if(ntohl(fl->sa_family) == AF_INET){
				s.erase(0,2);
			}
		break;
		case ASRCIP4: // orez 
			for(int i = 0; i < 12; i++){
				tmp.s6_addr[i] = 0x00;
			}
			for(int i = 12; i < 16; i++){
				if(mask - 8 >= 0){
					mask -= 8;
					tmp.s6_addr[i] = fl->src_addr.s6_addr[i];		
				} else {
					int x = 8 - mask%8;
					Mask <<= x;
					tmp.s6_addr[i] = fl->src_addr.s6_addr[i] & Mask;
					for(i++; i< 16;i++){
						tmp.s6_addr[i] = 0x00;
					} 
				}	
			}
			fl->src_addr = tmp;

			inet_ntop(AF_INET6, &(tmp), ip, INET6_ADDRSTRLEN);
			s = ip;
			s.erase(0,2);
		break;
		case ASRCIP6: 
			for(int i = 0; i < 16; i++){
				if(mask - 8 >= 0){
					mask -= 8;
					tmp.s6_addr[i] = fl->src_addr.s6_addr[i];		
				} else {
					int x = 8 - mask%8;
					Mask <<= x;
					tmp.s6_addr[i] = fl->src_addr.s6_addr[i] & Mask;
					for(i++; i< 16;i++){
						tmp.s6_addr[i] = 0x00;
					} 
				}
			}
			fl->src_addr = tmp;
			inet_ntop(AF_INET6, &(fl->src_addr), ip, INET6_ADDRSTRLEN);
			s = ip;
		break;
		case ADSTIP:
			inet_ntop(AF_INET6, &(fl->dst_addr), ip, INET6_ADDRSTRLEN);
			s = ip;
			if(ntohl(fl->sa_family) == AF_INET){
				s.erase(0,2);
			} 
		break;
		case ADSTIP4: // orez
			for(int i = 0; i < 12; i++){
				tmp.s6_addr[i] = 0x00;
			}
			for(int i = 12; i < 16; i++){
				if(mask - 8 >= 0){
					mask -= 8;
					tmp.s6_addr[i] = fl->dst_addr.s6_addr[i];		
				} else {
					int x = 8 - mask%8;
					Mask <<= x;
					tmp.s6_addr[i] = fl->dst_addr.s6_addr[i] & Mask;
					for(i++; i< 16;i++){
						tmp.s6_addr[i] = 0x00;
					} 
				}
			}
			fl->dst_addr = tmp;
			inet_ntop(AF_INET6, &(fl->dst_addr), ip, INET6_ADDRSTRLEN);
			s = ip;
			s.erase(0,2); 
		break;
		case ADSTIP6: 
			for(int i = 0; i < 16; i++){
				if(mask - 8 >= 0){
					mask -= 8;
					tmp.s6_addr[i] = fl->dst_addr.s6_addr[i];		
				} else {
					int x = 8 - mask%8;
					Mask <<= x;
					tmp.s6_addr[i] = fl->dst_addr.s6_addr[i] & Mask;
					for(i++; i< 16;i++){
						tmp.s6_addr[i] = 0x00;
					} 
				}
			}
			fl->dst_addr = tmp;
			inet_ntop(AF_INET6, &(fl->dst_addr), ip, INET6_ADDRSTRLEN);
			s = ip; 
		break;
		default: break;
	}
	got = map.find(s);
	if(got != map.end()){
		map[s].bytes += __builtin_bswap64(fl->bytes);
		map[s].packets += __builtin_bswap64(fl->packets);
	} else {
		map[s] = d;
		map[s].ip = s;
		map[s].port = 0;
		map[s].bytes = __builtin_bswap64(fl->bytes);
		map[s].packets = __builtin_bswap64(fl->packets);
	}
	params->ipMaskOrPort = (char *) str.c_str();
}

void parsePacket(struct param* params, struct flow * fl, std::unordered_map<uint16_t, struct data> &map){

	struct data d;
	uint16_t port = 0;
	std::unordered_map<uint16_t, struct data>::const_iterator got;
	switch(params->aggregationTypeId){
		case ASRCPORT:
			port = fl->src_port; 
			break;
		case ADSTPORT: 
			port = fl->dst_port;
			break;
		default : break;
	}

	got = map.find(port);
	if(got != map.end()){	
		map[port].bytes += __builtin_bswap64(fl->bytes);
		map[port].packets += __builtin_bswap64(fl->packets);
	} else {
		map[port] = d;
		map[port].ip = "";
		map[port].port = ntohs(port);
		map[port].bytes = __builtin_bswap64(fl->bytes);
		map[port].packets = __builtin_bswap64(fl->packets);
	}
}

// cteni souboru
void readFile(struct param* params, char *fileName, std::unordered_map<uint16_t, struct data> &map1, std::unordered_map<std::string, struct data> &map2){
	FILE * fp = fopen(fileName, "rb");
	if(fp == NULL){
		fprintf(stderr, "Nepodarilo se otevrit soubor %s", fileName);
		exit(1); // nestacil by return?
	}
	struct flow fl;
	size_t n = 0;
	while((n = fread(&fl, sizeof(struct flow), 1, fp )) != 0){
		if((params->aggregationTypeId == ASRCIP4 ||
			params->aggregationTypeId == ADSTIP4) &&
			ntohl(fl.sa_family) == AF_INET) {
			parsePacket(params,&fl,map2);
		} else if ((params->aggregationTypeId == ASRCIP6 ||
			params->aggregationTypeId == ADSTIP6) &&
			ntohl(fl.sa_family) == AF_INET6) {
			parsePacket(params,&fl,map2);
		} else {
			if((params->aggregationTypeId == ASRCPORT) || (params->aggregationTypeId == ADSTPORT)){
				parsePacket(params,&fl,map1);	
			} else {
				parsePacket(params,&fl,map2);
			}

		}
	}
	fclose(fp);
}

void readPath(struct param *params, std::unordered_map<uint16_t, struct data> &map1, std::unordered_map<std::string, struct data> &map2){
	struct stat st;
	std::vector<std::string> dirs;
	std::string file = params->directory;
	dirs.push_back(file);
	DIR *dir;

	struct dirent *de;
	while(!dirs.empty()){
		file = dirs.front();
		dirs.erase(dirs.begin());
		if((lstat(file.c_str(), &st)) < 0){
			fprintf(stderr, "Chyba pri nacitani lstat");
			freeAll(params);
			exit(1);
		}
		switch(st.st_mode & S_IFMT){
			case S_IFDIR:
				if((dir = opendir(file.c_str())) != NULL){
					while((de = readdir(dir)) != NULL){
						if((strcmp(de->d_name, "..") != 0) && (strcmp(de->d_name,".") != 0)){
							std::string nf;
							if(*file.rbegin() != '/'){
								nf = file + "/" + de->d_name;
							} else {
								nf = file + de->d_name;
							}
							dirs.push_back(nf);
						}
					}
				}
				closedir(dir);
				break;
			case S_IFREG:
				readFile(params, (char *)file.c_str(), map1, map2);
				break;
			default:
				fprintf(stderr,"%s neni nazvem slozky ani souboru", file.c_str());
				break;
			}
	}
}

void sortMapsToVect(struct param *params, std::unordered_map<uint16_t, struct data> &map1, std::unordered_map<std::string, struct data> &map2, std::vector<data> &vec){
    if(params->aggregationTypeId == ASRCPORT || params->aggregationTypeId == ADSTPORT){	
		for (std::unordered_map<uint16_t, struct data>::iterator it = map1.begin(); it!= map1.end(); it++) {
			vec.push_back(it->second);
		}
	} else {
		for (std::unordered_map<std::string, struct data>::iterator it = map2.begin(); it!= map2.end(); it++) {
			vec.push_back(it->second);
		}
	}

	if(params->sortTypeId == SBYTES){
		std::sort(vec.begin(),vec.end(),sortByBytes);
	} else {
		std::sort(vec.begin(),vec.end(),sortByPackets);
	}
}

void print(struct param *params, std::vector<struct data> v){
	switch(params->aggregationTypeId){
		case ASRCIP:
		case ASRCIP4:
		case ASRCIP6:
			std::cout << "#srcip,packets,bytes" << std::endl;
			break;
		case ADSTIP:
		case ADSTIP4:
		case ADSTIP6:
			std::cout << "#dstip,packets,bytes" << std::endl;
			break;
		case ASRCPORT:
			std::cout << "#srcport,packets,bytes" << std::endl;
			break;
		case ADSTPORT:
			std::cout << "#dstport,packets,bytes" << std::endl;
			break;
		default: break;
	}
	if(params->aggregationTypeId == ADSTPORT || params->aggregationTypeId == ASRCPORT){
		for(unsigned int i = 0; i < v.size(); i++ ){
			std::cout << v[i].port<<","<< v[i].packets << "," << v[i].bytes << std::endl;
	//		printf("%" PRIi16 ",%" PRIi64 ",%" PRIi64 "\n", __builtin_bswap16(v[i].port), __builtin_bswap64(v[i].packets), __builtin_bswap64(v[i].bytes) );
		}
	} else {
		for(unsigned int i = 0; i < v.size(); i++ ){
			if(v[i].ip == ""){
				v[i].ip = "0.0.0.0";
			}
			std::cout << v[i].ip<<","<< v[i].packets << "," << v[i].bytes << std::endl;
	//		printf("%s,%" PRIi64 ",%" PRIi64 "\n", v[i].ip.c_str(),__builtin_bswap64(v[i].packets), __builtin_bswap64(v[i].bytes) );
		}
	}
}

int main(int argc, char *argv[]){
	struct param * params = parseParams(argc, argv);
	std::unordered_map<uint16_t, struct data> map1;
	std::unordered_map<std::string, struct data> map2;
	readPath(params, map1, map2);
	std::vector<struct data> vec;
	sortMapsToVect(params, map1, map2, vec);
	print(params, vec);
	return 0;
}

