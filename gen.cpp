#include <pcap.h>
#include <iostream>
#include <fstream>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <string.h>

// 回调函数，用于处理每个捕获的数据包
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    std::ofstream *outfile = reinterpret_cast<std::ofstream*>(userData);

    // 提取时间戳,并进行格式化
    timeval ts = pkthdr->ts;
    char timestamp[64];
    snprintf(timestamp, sizeof(timestamp), "%ld", ts.tv_sec);

    // 提取时间戳的后四位字符
    char last_four[5];  // 用来存储后四位字符的数组，包括字符串末尾的 '\0'
    if (strlen(timestamp) >= 4) {
        strcpy(last_four, timestamp + strlen(timestamp) - 4);
    } else {
        strcpy(last_four, timestamp);  // 如果字符串长度不足四位，则复制整个字符串
    }

    // 以太网头部
    const struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;

    // 仅处理IPv4数据包
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        const struct ip *ip_header;
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        
        // 源IP地址
        char src_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_src), src_ip, INET_ADDRSTRLEN);
        
        // 目的IP地址
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip_header->ip_dst), dst_ip, INET_ADDRSTRLEN);
        
        // 写入输出文件
        *outfile << last_four << " " << src_ip << "-" << dst_ip << std::endl;
    }
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <pcap file> <output file>" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // 打开PCAP文件
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_offline() failed: " << errbuf << std::endl;
        return 1;
    }

    // 打开输出文件
    std::ofstream outfile(argv[2]);
    if (!outfile.is_open()) {
        std::cerr << "Failed to open output file: " << argv[2] << std::endl;
        return 1;
    }

    // 开始捕获数据包
    pcap_loop(handle, 0, packetHandler, reinterpret_cast<u_char*>(&outfile));

    pcap_close(handle);
    outfile.close();
    return 0;
}

//g++ gen.cpp -o gen -lpcap
//./gen ../small-pcap/0.pcap key.txt
