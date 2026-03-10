// ============================================================================
// C++ 網路監控系統 - 核心代碼框架 (Week 1-2)
// ============================================================================

// ============================================================================
// 1. 協議標頭定義 - ProtocolHeaders.h
// ============================================================================

#pragma once
#include <cstdint>
#include <cstring>

#pragma pack(push, 1)  // 禁用結構體對齊

// ===== Ethernet 標頭 =====
struct EthernetHeader {
    uint8_t destination_mac[6];    // 目的 MAC 地址
    uint8_t source_mac[6];         // 源 MAC 地址
    uint16_t ether_type;           // 協議類型 (0x0800=IPv4, 0x0806=ARP, 0x86DD=IPv6)
    
    // 網位元序（大端）轉主機序列常見類型
    static const uint16_t ETHER_TYPE_IP   = 0x0800;
    static const uint16_t ETHER_TYPE_ARP  = 0x0806;
    static const uint16_t ETHER_TYPE_IPV6 = 0x86DD;
};

// ===== IPv4 標頭 =====
struct IPv4Header {
    uint8_t version_ihl;              // 版本 (4 bits) + IHL (4 bits)
    uint8_t dscp_ecn;                 // DSCP (6 bits) + ECN (2 bits)
    uint16_t total_length;            // 總長度 (包括標頭和數據)
    uint16_t identification;          // 標識
    uint16_t flags_fragment_offset;   // 標誌 (3 bits) + 片段偏移 (13 bits)
    uint8_t ttl;                      // TTL (Time To Live)
    uint8_t protocol;                 // 協議 (6=TCP, 17=UDP, 1=ICMP)
    uint16_t header_checksum;         // 標頭校驗和
    uint32_t source_ip;               // 源 IP 地址
    uint32_t destination_ip;          // 目的 IP 地址
    
    // 協議常數
    static const uint8_t PROTOCOL_ICMP = 1;
    static const uint8_t PROTOCOL_TCP  = 6;
    static const uint8_t PROTOCOL_UDP  = 17;
    
    uint8_t get_version() const { return (version_ihl >> 4) & 0x0F; }
    uint8_t get_ihl() const { return version_ihl & 0x0F; }
};

// ===== TCP 標頭 =====
struct TCPHeader {
    uint16_t source_port;             // 源埠號
    uint16_t destination_port;        // 目的埠號
    uint32_t sequence_number;         // 序列號
    uint32_t acknowledgement_number;  // 確認號
    uint8_t data_offset_reserved;     // 數據偏移 (4 bits) + 保留 (3 bits) + NS (1 bit)
    uint8_t flags;                    // 標誌位
    uint16_t window_size;             // 窗口大小
    uint16_t checksum;                // 校驗和
    uint16_t urgent_pointer;          // 緊急指針
    
    // TCP 標誌常數
    static const uint8_t FLAG_FIN = 0x01;  // 結束
    static const uint8_t FLAG_SYN = 0x02;  // 同步
    static const uint8_t FLAG_RST = 0x04;  // 重設
    static const uint8_t FLAG_PSH = 0x08;  // 推送
    static const uint8_t FLAG_ACK = 0x10;  // 確認
    static const uint8_t FLAG_URG = 0x20;  // 緊急
    
    uint8_t get_data_offset() const { return (data_offset_reserved >> 4) & 0x0F; }
    bool has_syn() const { return (flags & FLAG_SYN) != 0; }
    bool has_ack() const { return (flags & FLAG_ACK) != 0; }
    bool has_fin() const { return (flags & FLAG_FIN) != 0; }
    bool has_rst() const { return (flags & FLAG_RST) != 0; }
};

// ===== UDP 標頭 =====
struct UDPHeader {
    uint16_t source_port;             // 源埠號
    uint16_t destination_port;        // 目的埠號
    uint16_t length;                  // 長度（包括標頭和數據）
    uint16_t checksum;                // 校驗和
};

// ===== DNS 標頭 =====
struct DNSHeader {
    uint16_t transaction_id;          // 事務 ID
    uint16_t flags;                   // 標誌
    uint16_t questions;               // 問題數
    uint16_t answer_rrs;              // 答案資源記錄數
    uint16_t authority_rrs;           // 授權資源記錄數
    uint16_t additional_rrs;          // 附加資源記錄數
};

// ===== ARP 標頭 =====
struct ARPHeader {
    uint16_t hardware_type;           // 硬件類型 (1=Ethernet)
    uint16_t protocol_type;           // 協議類型 (0x0800=IPv4)
    uint8_t hardware_address_length;  // 硬件地址長度 (6 for MAC)
    uint8_t protocol_address_length;  // 協議地址長度 (4 for IPv4)
    uint16_t operation;               // 操作 (1=Request, 2=Reply)
    uint8_t sender_mac[6];            // 發送方 MAC
    uint32_t sender_ip;               // 發送方 IP
    uint8_t target_mac[6];            // 目標 MAC
    uint32_t target_ip;               // 目標 IP
};

#pragma pack(pop)

// ===== 輔助函式 =====
inline std::string mac_to_string(const uint8_t* mac) {
    char buffer[18];
    snprintf(buffer, sizeof(buffer), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buffer);
}

inline std::string ip_to_string(uint32_t ip) {
    char buffer[16];
    snprintf(buffer, sizeof(buffer), "%d.%d.%d.%d",
             (ip >> 0) & 0xFF, (ip >> 8) & 0xFF, 
             (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
    return std::string(buffer);
}

inline uint16_t ntohs(uint16_t netshort) {
    return ((netshort & 0xFF) << 8) | ((netshort >> 8) & 0xFF);
}

inline uint32_t ntohl(uint32_t netlong) {
    return ((netlong & 0xFF) << 24) | ((netlong & 0xFF00) << 8) |
           ((netlong >> 8) & 0xFF00) | ((netlong >> 24) & 0xFF);
}


// ============================================================================
// 2. 封包特徵提取 - PacketFeature.h
// ============================================================================

#pragma once
#include <string>
#include <ctime>

struct PacketFeature {
    // 時間戳
    uint64_t timestamp_ms;
    uint32_t timestamp_us;
    
    // Ethernet 層
    std::string src_mac;
    std::string dst_mac;
    
    // IP 層
    std::string src_ip;
    std::string dst_ip;
    uint8_t protocol;           // TCP=6, UDP=17, ICMP=1
    uint8_t ttl;
    uint16_t packet_id;
    bool is_fragmented;
    
    // TCP/UDP 層
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    
    // TCP 特有
    uint8_t tcp_flags = 0;
    uint32_t seq_num = 0;
    uint32_t ack_num = 0;
    
    // 通用
    uint32_t packet_length;
    uint32_t payload_length;     // 實際數據長度
    
    // 協議分類
    bool is_tcp() const { return protocol == 6; }
    bool is_udp() const { return protocol == 17; }
    bool is_icmp() const { return protocol == 1; }
    bool is_dns() const { return is_udp() && dst_port == 53; }
    bool is_http() const { return is_tcp() && (dst_port == 80 || src_port == 80); }
    bool is_https() const { return is_tcp() && (dst_port == 443 || src_port == 443); }
};


// ============================================================================
// 3. 環形緩衝區 - RingBuffer.h
// ============================================================================

#pragma once
#include <deque>
#include <mutex>
#include <condition_variable>
#include <memory>

template<typename T>
class RingBuffer {
private:
    std::deque<T> buffer;
    mutable std::mutex mtx;
    std::condition_variable cv;
    const size_t MAX_SIZE;
    
public:
    explicit RingBuffer(size_t max_size = 10000) : MAX_SIZE(max_size) {}
    
    // 推入元素
    void push(const T& item) {
        std::unique_lock<std::mutex> lock(mtx);
        
        // 如果滿了，移除最舊的
        if (buffer.size() >= MAX_SIZE) {
            buffer.pop_front();
        }
        
        buffer.push_back(item);
        cv.notify_one();  // 通知等待的消費者
    }
    
    void push(T&& item) {
        std::unique_lock<std::mutex> lock(mtx);
        if (buffer.size() >= MAX_SIZE) {
            buffer.pop_front();
        }
        buffer.push_back(std::move(item));
        cv.notify_one();
    }
    
    // 嘗試彈出元素
    bool try_pop(T& item) {
        std::unique_lock<std::mutex> lock(mtx);
        if (buffer.empty()) {
            return false;
        }
        item = std::move(buffer.front());
        buffer.pop_front();
        return true;
    }
    
    // 等待彈出（阻塞等待）
    bool wait_pop(T& item, int timeout_ms = -1) {
        std::unique_lock<std::mutex> lock(mtx);
        
        if (timeout_ms < 0) {
            // 無限等待
            cv.wait(lock, [this] { return !buffer.empty(); });
        } else {
            // 有限等待
            if (!cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                             [this] { return !buffer.empty(); })) {
                return false;
            }
        }
        
        item = std::move(buffer.front());
        buffer.pop_front();
        return true;
    }
    
    size_t size() const {
        std::unique_lock<std::mutex> lock(mtx);
        return buffer.size();
    }
    
    bool empty() const {
        std::unique_lock<std::mutex> lock(mtx);
        return buffer.empty();
    }
    
    void clear() {
        std::unique_lock<std::mutex> lock(mtx);
        buffer.clear();
    }
};


// ============================================================================
// 4. 協議解析器 - ProtocolParser.h
// ============================================================================

#pragma once
#include "ProtocolHeaders.h"
#include "PacketFeature.h"
#include <vector>

class ProtocolParser {
public:
    // 靜態解析函式
    static PacketFeature parse_packet(const uint8_t* packet_data, uint32_t packet_length);
    
private:
    static EthernetHeader* parse_ethernet(const uint8_t* data, uint32_t& offset);
    static IPv4Header* parse_ipv4(const uint8_t* data, uint32_t& offset);
    static TCPHeader* parse_tcp(const uint8_t* data, uint32_t& offset);
    static UDPHeader* parse_udp(const uint8_t* data, uint32_t& offset);
    static ARPHeader* parse_arp(const uint8_t* data, uint32_t& offset);
};


// ============================================================================
// 5. 協議解析器實作 - ProtocolParser.cpp
// ============================================================================

#include "ProtocolParser.h"
#include <cstring>
#include <chrono>

PacketFeature ProtocolParser::parse_packet(const uint8_t* packet_data, uint32_t packet_length) {
    PacketFeature feature;
    feature.packet_length = packet_length;
    
    // 獲取時間戳
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch());
    feature.timestamp_ms = ms.count();
    
    uint32_t offset = 0;
    
    if (packet_length < sizeof(EthernetHeader)) {
        return feature;  // 太短，無法解析
    }
    
    // 解析 Ethernet 層
    auto* eth_hdr = (EthernetHeader*)(packet_data + offset);
    feature.src_mac = mac_to_string(eth_hdr->source_mac);
    feature.dst_mac = mac_to_string(eth_hdr->destination_mac);
    offset += sizeof(EthernetHeader);
    
    uint16_t ether_type = ntohs(eth_hdr->ether_type);
    
    // 解析 IP 層（暫時只支援 IPv4）
    if (ether_type == EthernetHeader::ETHER_TYPE_IP) {
        if (offset + sizeof(IPv4Header) > packet_length) {
            return feature;
        }
        
        auto* ip_hdr = (IPv4Header*)(packet_data + offset);
        feature.src_ip = ip_to_string(ntohl(ip_hdr->source_ip));
        feature.dst_ip = ip_to_string(ntohl(ip_hdr->destination_ip));
        feature.protocol = ip_hdr->protocol;
        feature.ttl = ip_hdr->ttl;
        feature.packet_id = ntohs(ip_hdr->identification);
        
        uint8_t ihl = ip_hdr->get_ihl();
        offset += ihl * 4;
        
        // 根據協議解析上層
        if (ip_hdr->protocol == IPv4Header::PROTOCOL_TCP) {
            if (offset + sizeof(TCPHeader) > packet_length) {
                return feature;
            }
            
            auto* tcp_hdr = (TCPHeader*)(packet_data + offset);
            feature.src_port = ntohs(tcp_hdr->source_port);
            feature.dst_port = ntohs(tcp_hdr->destination_port);
            feature.tcp_flags = tcp_hdr->flags;
            feature.seq_num = ntohl(tcp_hdr->sequence_number);
            feature.ack_num = ntohl(tcp_hdr->acknowledgement_number);
            
            uint8_t data_offset = tcp_hdr->get_data_offset();
            feature.payload_length = packet_length - offset - (data_offset * 4);
            
        } else if (ip_hdr->protocol == IPv4Header::PROTOCOL_UDP) {
            if (offset + sizeof(UDPHeader) > packet_length) {
                return feature;
            }
            
            auto* udp_hdr = (UDPHeader*)(packet_data + offset);
            feature.src_port = ntohs(udp_hdr->source_port);
            feature.dst_port = ntohs(udp_hdr->destination_port);
            feature.payload_length = ntohs(udp_hdr->length) - sizeof(UDPHeader);
        }
    }
    // ARP 層
    else if (ether_type == EthernetHeader::ETHER_TYPE_ARP) {
        if (offset + sizeof(ARPHeader) > packet_length) {
            return feature;
        }
        
        auto* arp_hdr = (ARPHeader*)(packet_data + offset);
        feature.src_ip = ip_to_string(ntohl(arp_hdr->sender_ip));
        feature.dst_ip = ip_to_string(ntohl(arp_hdr->target_ip));
        feature.protocol = 0;  // 特殊標記為 ARP
    }
    
    return feature;
}


// ============================================================================
// 6. 主程式骨架 - main.cpp (Week 1)
// ============================================================================

#include <iostream>
#include <pcap.h>
#include "ProtocolParser.h"
#include "RingBuffer.h"

#ifdef _WIN32
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib")
    #pragma comment(lib, "iphlpapi.lib")
#endif

// 全局緩衝區
RingBuffer<PacketFeature> packet_buffer(10000);

void packet_handler(u_char* user, const struct pcap_pkthdr* header,
                    const u_char* packet_data) {
    // 解析封包
    PacketFeature feature = ProtocolParser::parse_packet(packet_data, header->len);
    
    // 推入環形緩衝區
    packet_buffer.push(feature);
}

int main() {
    pcap_if_t* devices = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    
    // 列舉設備
    if (pcap_findalldevs(&devices, error_buffer) == -1) {
        std::cerr << "Error finding devices: " << error_buffer << std::endl;
        return 1;
    }
    
    // 顯示可用設備
    int count = 0;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        std::cout << "[" << count++ << "] " << device->name << std::endl;
        if (device->description) {
            std::cout << "    Description: " << device->description << std::endl;
        }
    }
    
    // 選擇第一個設備
    if (devices == nullptr) {
        std::cerr << "No devices found" << std::endl;
        return 1;
    }
    
    // 打開設備
    pcap_t* handle = pcap_open_live(devices->name, BUFSIZ, 0, 1000, error_buffer);
    if (!handle) {
        std::cerr << "Error opening device: " << error_buffer << std::endl;
        pcap_freealldevs(devices);
        return 1;
    }
    
    std::cout << "Start capturing on " << devices->name << std::endl;
    std::cout << "Press Ctrl+C to stop" << std::endl;
    
    // 設定過濾規則（可選）
    // pcap_compile(handle, ???, "tcp port 80", 0, ???);
    
    // 開始捕獲
    pcap_loop(handle, 0, packet_handler, nullptr);
    
    // 統計
    std::cout << "\nTotal packets captured: " << packet_buffer.size() << std::endl;
    
    // 清理
    pcap_close(handle);
    pcap_freealldevs(devices);
    
    return 0;
}


// ============================================================================
// 7. 多執行緒監控系統 - NetworkMonitor.h (Week 3)
// ============================================================================

#pragma once
#include <thread>
#include <atomic>
#include "RingBuffer.h"
#include "PacketFeature.h"

class NetworkMonitor {
private:
    std::thread capture_thread;
    std::thread analysis_thread;
    std::atomic<bool> running{false};
    
    RingBuffer<PacketFeature> packet_buffer;
    
    // 統計數據
    std::atomic<uint64_t> total_packets{0};
    std::atomic<uint64_t> total_bytes{0};
    
public:
    NetworkMonitor() : packet_buffer(10000) {}
    
    bool start(const char* device_name);
    void stop();
    
    uint64_t get_total_packets() const { return total_packets; }
    uint64_t get_total_bytes() const { return total_bytes; }
    
private:
    void capture_worker(const char* device_name);
    void analysis_worker();
};

/*
在 NetworkMonitor.cpp 中實作:

void NetworkMonitor::capture_worker(const char* device_name) {
    // 使用 pcap 抓包
    // 推入 packet_buffer
    // 更新 total_packets, total_bytes
}

void NetworkMonitor::analysis_worker() {
    while (running) {
        PacketFeature feature;
        if (packet_buffer.wait_pop(feature, 100)) {
            // 分析封包
            // 更新統計
            // 檢查威脅
        }
    }
}
*/

// ============================================================================
// 8. 攻擊偵測引擎 - DetectionEngine.h (Week 5)
// ============================================================================

#pragma once
#include <map>
#include <set>
#include <string>
#include "PacketFeature.h"

struct AlertEvent {
    std::string attack_type;   // "SYN_FLOOD", "PORT_SCAN", etc.
    std::string source_ip;
    std::string severity;      // "LOW", "MEDIUM", "HIGH", "CRITICAL"
    std::string message;
    uint64_t timestamp_ms;
};

class DetectionEngine {
public:
    DetectionEngine() = default;
    
    // 分析單個封包
    std::vector<AlertEvent> analyze_packet(const PacketFeature& feature);
    
private:
    // 偵測模組
    std::vector<AlertEvent> check_syn_flood(const PacketFeature& feature);
    std::vector<AlertEvent> check_port_scan(const PacketFeature& feature);
    std::vector<AlertEvent> check_arp_spoofing(const PacketFeature& feature);
    
    // 統計數據
    std::map<std::string, int> syn_counts;  // IP -> SYN count
    std::map<std::string, std::set<uint16_t>> port_history;  // IP -> Port set
    std::map<std::string, std::set<std::string>> arp_table;  // IP -> MAC set
};

/*
實作偵測邏輯:

std::vector<AlertEvent> DetectionEngine::check_syn_flood(const PacketFeature& feature) {
    std::vector<AlertEvent> alerts;
    
    if (feature.is_tcp() && (feature.tcp_flags & TCPHeader::FLAG_SYN)) {
        syn_counts[feature.src_ip]++;
        
        if (syn_counts[feature.src_ip] > 100) {
            AlertEvent alert{
                "SYN_FLOOD",
                feature.src_ip,
                "CRITICAL",
                "Excessive SYN packets detected",
                feature.timestamp_ms
            };
            alerts.push_back(alert);
        }
    }
    
    return alerts;
}

std::vector<AlertEvent> DetectionEngine::check_port_scan(const PacketFeature& feature) {
    std::vector<AlertEvent> alerts;
    
    if (feature.is_tcp()) {
        port_history[feature.src_ip].insert(feature.dst_port);
        
        if (port_history[feature.src_ip].size() > 20) {
            AlertEvent alert{
                "PORT_SCAN",
                feature.src_ip,
                "HIGH",
                "Port scanning detected",
                feature.timestamp_ms
            };
            alerts.push_back(alert);
        }
    }
    
    return alerts;
}
*/

// ============================================================================
// 9. 日誌系統 - Logger.h (Week 7)
// ============================================================================

#pragma once
#include <fstream>
#include <json/json.h>
#include "DetectionEngine.h"

class Logger {
private:
    std::ofstream log_file;
    std::string log_path;
    
public:
    Logger(const std::string& filepath) : log_path(filepath) {
        log_file.open(filepath, std::ios::app);
    }
    
    ~Logger() {
        if (log_file.is_open()) {
            log_file.close();
        }
    }
    
    void log_alert(const AlertEvent& alert) {
        Json::Value json_alert;
        json_alert["type"] = alert.attack_type;
        json_alert["source_ip"] = alert.source_ip;
        json_alert["severity"] = alert.severity;
        json_alert["message"] = alert.message;
        json_alert["timestamp"] = alert.timestamp_ms;
        
        Json::StreamWriterBuilder writer;
        log_file << Json::writeString(writer, json_alert) << "\n";
        log_file.flush();
    }
};

// ============================================================================
// 編譯命令 (CMakeLists.txt)
// ============================================================================

/*
cmake_minimum_required(VERSION 3.10)
project(NetworkMonitor)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 查找 libpcap
find_package(PCAP REQUIRED)

# 主程式
add_executable(network_monitor
    src/main.cpp
    src/ProtocolParser.cpp
    src/NetworkMonitor.cpp
    src/DetectionEngine.cpp
)

target_include_directories(network_monitor PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(network_monitor PRIVATE
    ${PCAP_LIBRARIES}
)

# 單元測試
add_executable(test_parser
    test/test_parser.cpp
    src/ProtocolParser.cpp
)
*/

// ============================================================================
// 編譯指令 (Visual Studio)
// ============================================================================

/*
1. 新建 C++ 項目: NetworkMonitor (Console App)

2. 配置項目屬性:
   - 包含目錄 (Include Directories):
     C:\\npcap\\Include
     
   - 庫目錄 (Library Directories):
     C:\\npcap\\Lib\\x64
     
   - 連結器輸入 (Linker > Input > Additional Dependencies):
     wpcap.lib
     ws2_32.lib
     iphlpapi.lib

3. 編譯:
   Visual Studio > Build > Build Solution (Ctrl+Shift+B)

4. 運行:
   Debug > Start Debugging (F5)
*/

// ============================================================================
