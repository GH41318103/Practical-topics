# C++ 即時網路流量監控與攻擊偵測系統
## 專題開發完整計畫

---

## 📋 目錄
1. [八週開發時程表](#八週開發時程表)
2. [核心技術棧](#核心技術棧)
3. [實作建議與步驟](#實作建議與步驟)
4. [系統核心架構](#系統核心架構)
5. [攻擊偵測功能](#攻擊偵測功能)
6. [進階工具 - Snort 規則解析](#進階工具---snort-規則解析)
7. [效能優化挑戰](#效能優化挑戰)
8. [成果演示方案](#成果演示方案)

---

## 八週開發時程表

| 週次 | 階段 | 重點任務 | 交付物 |
|------|------|--------|--------|
| **W1** | 環境與基礎 | 安裝 Npcap/libpcap；實作「列出網卡」與「基本抓包」功能 | 可以列出並選擇網卡；抓到原始封包並打印 |
| **W2** | 協定解析層 | 實作 Ethernet/IP/TCP/UDP 標頭解析，提取 IP、Port、Flags | 能正確解析並顯示 Source/Dest IP、協議、Port |
| **W3** | 核心架構架設 | 建立 Ring Buffer 與 多執行緒（執行緒 A 抓包、B 處理）| 多執行緒運作穩定，無資料競爭問題 |
| **W4** | 預處理引擎 | 提取特徵（TTL、Payload 大小、TCP Flags），建立流量計數器 | 每秒統計 PPS、Mbps，記錄各 IP 連線統計 |
| **W5** | 偵測邏輯實作 | 完成 靜態規則（SYN Flood）與 動態基準（流量暴增）演算法 | 能偵測 SYN Flood、Port Scan、ARP Spoofing |
| **W6** | 進階功能 | 實作簡易 Snort Rule 解析器，讀取外部 .rules 檔案 | 支援外部規則檔，可動態新增偵測邏輯 |
| **W7** | 告警與介面 | 實作告警模組（日誌記錄、UI 紅框警示）；開發簡單的統計儀表板 | CLI 儀表板顯示即時流量、攻擊警告；JSON 日誌文件 |
| **W8** | 測試與演示 | 使用 Scapy 模擬攻擊，優化高負載下的偵測準確度 | Demo 視頻；壓力測試報告；最終版本代碼 |

---

## 核心技術棧

### 封包擷取層
```
Windows: Npcap SDK v1.3+ 
        或 WinPcap (舊版，不推薦)
        
Linux/macOS: libpcap v1.9+
```

### C++ 開發框架
```
推薦框架: PcapPlusPlus
- 現代 C++ 封裝（C++11/14 支援）
- 支援 Npcap、libpcap 雙平台
- 原生支援 DNS、HTTP、SSL 等應用層協議解析
- 官方文檔：https://seladb.github.io/PcapPlusPlus-Doc/
```

### 圖形介面選項
```
簡單版 (推薦第一階段): 
- CLI + 彩色輸出 (Windows: Windows Console API / Linux: ncurses)
- 進度條顯示即時統計

進階版 (W7 之後):
- Qt 6 (跨平台，易於繪製圖表)
- 或 ImGui (輕量級，適合實時監控 UI)
```

### 資料結構與工具
```cpp
// 流量統計
std::unordered_map<std::string, TrafficStats> ip_statistics;
std::deque<uint64_t> traffic_history;  // 5 分鐘的每秒流量樣本

// 多執行緒
std::thread capture_thread, analysis_thread;
std::condition_variable packet_notify;
std::mutex packet_queue_mutex;

// 日誌與規則
std::ofstream alert_log("alerts.json");
sqlite3* alert_database;  // 可選：存儲長期統計
```

---

## 實作建議與步驟

### 階段 1：環境搭建與基本抓包 (第 1-2 天)

#### Windows 環境設置
```bash
# 1. 下載 Npcap SDK
下載位址：https://nmap.org/download.html
選擇版本: Npcap v1.3+ SDK (x64 或 x86)

# 2. Visual Studio 新建 C++ 專案 (Console App)
專案名稱: NetworkMonitor
C++ 標準: C++17 或更高
Windows SDK 版本: 最新

# 3. 配置編譯環境
- 包含目錄: <Npcap SDK>/Include
- 庫目錄: <Npcap SDK>/Lib/x64 (或 x86)
- 連結器輸入: wpcap.lib ws2_32.lib iphlpapi.lib

# 4. 安裝 Npcap 驅動程式
執行 Npcap-x.x.x-oem.exe
選擇「Npcap OEM」或「公開版」（個人學習用公開版即可）
```

#### Linux 環境設置
```bash
# Ubuntu 22.04
sudo apt-get install libpcap-dev g++ cmake

# Fedora
sudo dnf install libpcap-devel gcc-c++ cmake

# macOS
brew install libpcap
```

#### C++ 第一個程式：列出網卡
```cpp
/*
 * file: list_devices.cpp
 * 目的: 列出電腦上所有網卡
 */
#include <iostream>
#include <pcap.h>

#ifdef _WIN32
    #pragma comment(lib, "wpcap.lib")
    #pragma comment(lib, "ws2_32.lib") 
    #pragma comment(lib, "iphlpapi.lib")
#endif

int main() {
    pcap_if_t* devices = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    
    // 列舉所有設備
    if (pcap_findalldevs(&devices, error_buffer) == -1) {
        std::cerr << "Error: " << error_buffer << std::endl;
        return 1;
    }
    
    int count = 0;
    for (pcap_if_t* device = devices; device != nullptr; device = device->next) {
        std::cout << "[" << count++ << "] " << device->name << std::endl;
        if (device->description) {
            std::cout << "    Description: " << device->description << std::endl;
        }
    }
    
    pcap_freealldevs(devices);
    return 0;
}
```

#### 第一個抓包程式：簡單捕獲
```cpp
#include <iostream>
#include <pcap.h>

void packet_handler(u_char* user, const struct pcap_pkthdr* header, 
                    const u_char* packet_data) {
    std::cout << "Packet captured: " << header->len << " bytes" << std::endl;
}

int main() {
    pcap_if_t* devices = nullptr;
    char error_buffer[PCAP_ERRBUF_SIZE] = {0};
    
    pcap_findalldevs(&devices, error_buffer);
    
    // 開啟第一張網卡
    pcap_t* handle = pcap_open_live(devices->name, BUFSIZ, 0, 1000, error_buffer);
    if (!handle) {
        std::cerr << "Error: " << error_buffer << std::endl;
        return 1;
    }
    
    std::cout << "Start capturing on " << devices->name << std::endl;
    pcap_loop(handle, 100, packet_handler, nullptr);  // 捕獲 100 個封包
    
    pcap_close(handle);
    pcap_freealldevs(devices);
    return 0;
}
```

---

## 系統核心架構

### 整體架構三層設計

```
┌────────────────────────────────────────────────────┐
│               告警與介面層 (Alert & GUI)             │
│  - 即時儀表板 (Dashboard)                           │
│  - 攻擊警告顯示 (Red Alert)                        │
│  - 統計圖表 (Charts)                               │
└────────────────────────────────────────────────────┘
                         △
                         │
┌────────────────────────────────────────────────────┐
│             偵測與分析層 (Detection Engine)         │
│  - 靜態規則匹配 (Static Rules)                    │
│  - 異常偵測 (Anomaly Detection)                   │
│  - 攻擊聯想 (Correlation)                         │
└────────────────────────────────────────────────────┘
                         △
                         │
┌────────────────────────────────────────────────────┐
│         封包處理層 (Packet Processing)              │
│  - Ring Buffer (環形緩衝)                         │
│  - 協定解析 (Protocol Parser)                    │
│  - 特徵提取 (Feature Extraction)                 │
│  - 多執行緒協調 (Thread Coordination)            │
└────────────────────────────────────────────────────┘
                         △
                         │
┌────────────────────────────────────────────────────┐
│        封包擷取層 (Packet Capture)                  │
│  - Npcap / libpcap 驅動呼叫                       │
│  - 網卡選擇 (NIC Selection)                      │
│  - 過濾規則 (BPF Filters)                        │
└────────────────────────────────────────────────────┘
```

### Ring Buffer 設計

```cpp
// PacketBuffer.h
#pragma once
#include <queue>
#include <vector>
#include <mutex>
#include <condition_variable>

struct PacketData {
    std::vector<uint8_t> data;
    uint32_t length;
    uint64_t timestamp_ms;
};

class RingBuffer {
private:
    std::deque<PacketData> buffer;
    std::mutex mtx;
    std::condition_variable cv;
    const size_t MAX_SIZE = 10000;
    
public:
    void push(const PacketData& packet);
    bool try_pop(PacketData& packet);
    size_t size() const;
};
```

### 多執行緒設計

```cpp
// NetworkMonitor.h
class NetworkMonitor {
private:
    std::thread capture_thread;
    std::thread analysis_thread;
    std::atomic<bool> running{false};
    RingBuffer packet_buffer;
    
    // 執行緒函式
    void capture_worker(const char* device_name, const char* filter);
    void analysis_worker();
    
public:
    bool start(const char* device_name);
    void stop();
};
```

**執行緒工作流程：**
```
[Capture Thread]
    ↓ pcap_next_ex()
    ↓ 解析基本標頭
    ↓ 推入 Ring Buffer
    ↓ 通知 Analysis Thread

[Analysis Thread]
    ↓ 睡眠 (條件變數等待)
    ↓ 從 Ring Buffer 提取封包
    ↓ 特徵提取
    ↓ 規則匹配
    ↓ 更新統計 & 觸發告警
```

---

## 攻擊偵測功能

### 支援偵測的三種攻擊

#### 1️⃣ SYN Flood (DDoS 攻擊)

**原理：**
- 攻擊者發送大量 SYN 封包但不完成三向交握
- 受害伺服器的半開放連線表滿溢

**偵測邏輯：**
```cpp
// DetectionEngine.cpp
bool detect_syn_flood() {
    static std::map<std::string, int> syn_counts;
    const int SYN_THRESHOLD = 100;      // 每秒超過 100 個 SYN 視為異常
    const int TIMEOUT_SEC = 5;
    
    for (auto& [src_ip, count] : syn_counts) {
        if (count > SYN_THRESHOLD) {
            alert("SYN Flood detected", src_ip, count);
            return true;
        }
    }
    return false;
}
```

**實作步驟：**
1. 在 TCP 層解析 Flags (SYN bit)
2. 按 Source IP 計數 SYN 封包
3. 每秒清空計數器並檢查是否超過閾值
4. 如果源 IP 的 SYN 次數 > 100 且 ACK 次數 < 10，判定為 SYN Flood

#### 2️⃣ Port Scanning (端口掃描)

**原理：**
- 攻擊者從同一 IP 對目標主機的多個不同連接埠進行連線嘗試
- 通常是攻擊前的偵測階段

**偵測邏輯：**
```cpp
bool detect_port_scan(const std::string& src_ip, uint16_t dst_port) {
    static std::map<std::string, std::set<uint16_t>> port_history;
    const int PORT_SCAN_THRESHOLD = 20;  // 5 秒內接觸超過 20 個不同 port
    
    port_history[src_ip].insert(dst_port);
    
    if (port_history[src_ip].size() > PORT_SCAN_THRESHOLD) {
        alert("Port Scan detected", src_ip, "Total ports: " + 
              std::to_string(port_history[src_ip].size()));
        return true;
    }
    return false;
}
```

**實作步驟：**
1. 使用 `std::set<uint16_t>` 按 Source IP 紀錄接觸過的目標 Port
2. 設定時間窗口（如 5 秒）
3. 若同一 IP 在時間窗口內觸及超過 20 個不同 Port，判定為掃描

#### 3️⃣ ARP Spoofing (ARP 欺騙)

**原理：**
- 攻擊者發送虛假的 ARP 回應，將自己的 MAC 位址綁定到別人的 IP
- 用於中間人攻擊或斷線他人網路

**偵測邏輯：**
```cpp
bool detect_arp_spoofing() {
    static std::map<std::string, std::set<std::string>> arp_table;
    // Map: IP -> Set<MAC>  若一個 IP 對應多個 MAC，即為欺騙
    
    for (auto& [ip, macs] : arp_table) {
        if (macs.size() > 1) {
            alert("ARP Spoofing detected", ip, 
                  "Multiple MACs: " + std::to_string(macs.size()));
            return true;
        }
    }
    return false;
}
```

**實作步驟：**
1. 監聽 ARP Reply 封包（Opcode = 2）
2. 提取 Sender IP 與 Sender MAC
3. 在本地 ARP 表中查詢該 IP
4. 如果 MAC 不相符，則判定為欺騙

### 靜態規則 vs 動態基準

#### 靜態規則（固定閾值）
```cpp
struct StaticRule {
    std::string rule_name;
    std::function<bool()> check_function;
    int severity;  // 1=low, 2=medium, 3=high
};

// 範例
StaticRule rule_syn_flood{
    "SYN Flood",
    []() { return detect_syn_flood(); },
    3
};
```

#### 動態基準（流量基線學習）
```cpp
class AnomalyDetector {
private:
    std::deque<uint64_t> traffic_history;  // 5 分鐘 × 60 秒 = 300 個樣本
    const size_t WINDOW_SIZE = 300;
    
public:
    bool is_anomaly(uint64_t current_traffic) {
        // 計算過去 5 分鐘的平均流量
        uint64_t sum = 0;
        for (auto t : traffic_history) sum += t;
        uint64_t baseline = sum / traffic_history.size();
        
        // 若當下流量 > 基線的 3 倍，判定為異常
        if (current_traffic > baseline * 3) {
            std::cout << "Anomaly: Current " << current_traffic 
                      << " vs Baseline " << baseline << std::endl;
            return true;
        }
        return false;
    }
};
```

---

## 進階工具 - Snort 規則解析

### Snort 規則格式速查

典型規則：
```
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
  (msg:"HTTP GET Request"; \
   flow:to_server,established; \
   content:"GET"; http_method; \
   sid:1000000; rev:1; classtype:web-application-activity;)
```

### 簡易規則解析器實作

```cpp
// SnortRuleParser.h
#pragma once
#include <string>
#include <vector>
#include <regex>

struct ParsedRule {
    std::string action;         // alert, drop, pass
    std::string protocol;       // tcp, udp, http, dns
    std::string src_ip;         // $EXTERNAL_NET, any, 192.168.1.0/24
    std::string src_port;       // any, 80, !22, [1:1024]
    std::string direction;      // ->, <->, <-
    std::string dst_ip;         // $HOME_NET, any
    std::string dst_port;       // any, 443, !80
    std::string msg;            // 規則描述
    int sid;                    // Signature ID
    std::vector<std::string> options;  // flow, content, pcre 等
};

class SnortRuleParser {
public:
    static ParsedRule parse_rule(const std::string& rule_line);
    static std::vector<ParsedRule> load_rules_from_file(const std::string& filepath);
};
```

### 解析實作細節

```cpp
// SnortRuleParser.cpp
ParsedRule SnortRuleParser::parse_rule(const std::string& rule_line) {
    ParsedRule rule;
    
    // 第一階段：正則提取基本結構
    std::regex base_pattern(
        R"((\w+)\s+(\w+)\s+([^\s]+)\s+([^\s]+)\s+(->|<->|<-)\s+([^\s]+)\s+([^\s]+)\s*\((.+)\))"
    );
    
    std::smatch match;
    if (!std::regex_match(rule_line, match, base_pattern)) {
        throw std::runtime_error("Invalid Snort rule format");
    }
    
    rule.action = match[1];
    rule.protocol = match[2];
    rule.src_ip = match[3];
    rule.src_port = match[4];
    rule.direction = match[5];
    rule.dst_ip = match[6];
    rule.dst_port = match[7];
    
    // 第二階段：解析 options
    std::string options_str = match[8];
    std::regex option_pattern(R"((\w+):([^;]+);)");
    
    std::sregex_iterator iter(options_str.begin(), options_str.end(), option_pattern);
    std::sregex_iterator end;
    
    for (; iter != end; ++iter) {
        std::string key = (*iter)[1];
        std::string value = (*iter)[2];
        
        if (key == "msg") {
            rule.msg = value;
        } else if (key == "sid") {
            rule.sid = std::stoi(value);
        }
        rule.options.push_back(key + ":" + value);
    }
    
    return rule;
}
```

### 規則檔範例 (rules/custom.rules)

```snort
# 偵測 HTTP 洪泛
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
  (msg:"HTTP Flood Attempt"; \
   flow:to_server,established; \
   threshold: type both, track by_src, count 100, seconds 1; \
   sid:3000001; rev:1;)

# 偵測異常 DNS 查詢
alert dns $EXTERNAL_NET any -> $HOME_NET 53 \
  (msg:"DNS Query Flood"; \
   dns_query; content:"."; \
   threshold: type both, track by_src, count 50, seconds 5; \
   sid:3000002; rev:1;)

# 偵測常見惡意軟體特徵
alert tcp $HOME_NET any -> $EXTERNAL_NET any \
  (msg:"Suspicious Outbound Connection"; \
   flow:to_server,established; \
   content:"User-Agent|3a|"; http_header; \
   content:"WinHttp"; http_header; within:100; \
   sid:3000003; rev:1;)
```

---

## 效能優化挑戰

### 挑戰 1：記憶體管理 - Ring Buffer 預分配

**問題：** 在高流量情況下頻繁分配/釋放記憶體導致性能下降

**解決方案：**
```cpp
// AdvancedRingBuffer.h
class PreAllocatedRingBuffer {
private:
    std::vector<uint8_t> buffer;
    std::vector<uint32_t> lengths;
    std::vector<uint64_t> timestamps;
    
    size_t write_ptr = 0;
    size_t read_ptr = 0;
    const size_t BUFFER_SIZE = 10 * 1024 * 1024;  // 10 MB 預分配
    const size_t MAX_PACKETS = 50000;
    
public:
    PreAllocatedRingBuffer() : buffer(BUFFER_SIZE), 
                               lengths(MAX_PACKETS), 
                               timestamps(MAX_PACKETS) {}
    
    bool write_packet(const uint8_t* data, uint32_t len);
    bool read_packet(uint8_t* out_data, uint32_t& len);
};
```

**性能收益：**
- 避免動態記憶體分配
- 減少 GC 暫停時間
- 預期吞吐量：100 Gbps 以上（單線程）

### 挑戰 2：執行緒同步 - 避免資料競爭

**問題：** 多執行緒下的 Race Condition 導致統計不準確

**解決方案：使用 Lock-Free 資料結構**
```cpp
// LockFreeStatistics.h
#include <atomic>

class LockFreeCounter {
private:
    std::atomic<uint64_t> count{0};
    
public:
    void increment(uint64_t delta = 1) {
        // CAS (Compare and Swap) 操作，無鎖
        count.fetch_add(delta, std::memory_order_relaxed);
    }
    
    uint64_t get() const {
        return count.load(std::memory_order_acquire);
    }
};

// 用於統計
std::map<std::string, std::atomic<uint64_t>> traffic_stats;
traffic_stats["total_packets"].fetch_add(1);
```

### 挑戰 3：CPU 效率 - 忙等避免

**問題：** Capture 執行緒無限循環檢查導致 CPU 使用率 100%

**解決方案：條件變數喚醒**
```cpp
void analysis_worker() {
    while (running) {
        std::unique_lock<std::mutex> lock(mtx);
        
        // 等待通知或 1 秒超時
        packet_notify.wait_for(lock, std::chrono::seconds(1),
            [this] { return !packet_buffer.empty(); });
        
        // 處理緩衝區中的封包
        PacketData pkt;
        while (packet_buffer.try_pop(pkt)) {
            analyze_packet(pkt);
        }
    }
}
```

### 挑戰 4：高效協定解析

**問題：** 逐位元檢查協定標頭太慢

**解決方案：使用位域結構**
```cpp
// ProtocolHeaders.h
#pragma pack(push, 1)  // 禁用對齊，緊湊存儲

struct EthernetHeader {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t type;  // 0x0800=IPv4, 0x0806=ARP
};

struct IPv4Header {
    uint8_t version_ihl;
    uint8_t dscp_ecn;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;  // 6=TCP, 17=UDP
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;  // bit 0=FIN, 1=SYN, 2=RST, ...
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};

#pragma pack(pop)
```

**優勢：**
- 直接內存映射，無需逐位元複製
- 解析時間：~100 ns / 封包

---

## 成果演示方案

### 完整演示流程

#### 第一幕：系統初始化 (30 秒)
```
▼ 開啟程式
  ✓ 載入配置檔
  ✓ 初始化 Npcap 驅動
  ✓ 列出可用網卡：
    [0] Intel Ethernet (主要)
    [1] VirtualBox (虛擬)
    [2] Cisco VPN Adapter
  ✓ 自動選擇 [0]
  ✓ 啟動捕獲執行緒
  ✓ 系統就緒
```

#### 第二幕：正常流量監控 (1 分鐘)
```
╔════════════════ NETWORK MONITOR v1.0 ════════════════╗
║                                                       ║
║  📊 即時統計                                          ║
║    Total Packets: 15,234 pps                         ║
║    Upstream: 245.3 Mbps   ↑                          ║
║    Downstream: 512.1 Mbps ↓                         ║
║                                                       ║
║  📍 Top Sources (IPv4)                               ║
║    192.168.1.100 ► 256.4 Mbps (Chrome - YouTube)   ║
║    192.168.1.101 ► 148.2 Mbps (Windows Updates)    ║
║    192.168.1.102 ► 87.3 Mbps (Slack)               ║
║                                                       ║
║  ✅ 狀態: 正常                                        ║
║                                                       ║
╚═══════════════════════════════════════════════════════╝

按 ESC 開始攻擊模擬...
```

#### 第三幕：模擬 Port Scanning 攻擊 (30 秒)
```bash
# 在另一個終端執行 Python Scapy 腳本
python3 simulate_port_scan.py --target 192.168.1.100 --ports 100

# 攻擊者 IP: 203.0.113.50
```

**監控軟體同時檢測到：**
```
╔════════════════ ATTACK ALERT ════════════════╗
║                                              ║
║ ⚠️  SEVERE: PORT SCAN DETECTED              ║
║                                              ║
║ Source IP: 203.0.113.50                     ║
║ Target: 192.168.1.100                       ║
║ Unique Ports Scanned: 73 in 10 seconds      ║
║                                              ║
║ Confidence: 96%                             ║
║ Action: LOGGED & ALERT                      ║
║                                              ║
╚══════════════════════════════════════════════╝

[時間軸]
[09:45:23.102] Port Scan suspected: 203.0.113.50 -> 192.168.1.100:22
[09:45:23.215] Port Scan suspected: 203.0.113.50 -> 192.168.1.100:23
[09:45:23.330] Port Scan suspected: 203.0.113.50 -> 192.168.1.100:25
...
[09:45:33.999] ALERT TRIGGERED: Port scan campaign detected from 203.0.113.50
```

#### 第四幕：模擬 SYN Flood DDoS 攻擊 (45 秒)
```bash
# 攻擊:
python3 simulate_syn_flood.py --target 192.168.1.100:80 --rate 5000

# 5000 個 SYN 封包/秒
```

**監控軟體即時反應：**
```
╔════════════════ CRITICAL ATTACK ════════════════╗
║                                                  ║
║ 🔴 SYN FLOOD - DISTRIBUTED DENIAL OF SERVICE    ║
║                                                  ║
║ Attack Severity: CRITICAL (99% confidence)     ║
║ Attack Duration: 45 seconds                    ║
║                                                 ║
║ Key Statistics:                                 ║
║   SYN Packets/sec: 5,127                        ║
║   ACK Packets/sec: 23                           ║
║   SYN:ACK Ratio: 223:1  (正常應為 1:1)          ║
║                                                 ║
║ Affected IPs:                                   ║
║   192.168.1.100:80 ◄─ 4,891 SYN packets       ║
║   192.168.1.100:443 ◄─ 236 SYN packets        ║
║                                                 ║
║ Recommended Action:                            ║
║   ⚡ Enable DDoS Mitigation                    ║
║   ⚡ Contact ISP                               ║
║                                                 ║
║ [實上線阻止] 等待確認...                       ║
║                                                 ║
╚══════════════════════════════════════════════════╝

📈 攻擊軍隊追蹤:
  [來自] 攻擊者網段: 198.51.100.0/24 (47 個獨立 IP)
  [目標] 受害者連接埠: 80, 443, 8080, 3306
  [特徵] TTL 異常: TTL=64 (有規律，非隨機)
```

#### 第五幕：ARP Spoofing 欺騙偵測 (20 秒)
```bash
# 攻擊:
python3 simulate_arp_spoofing.py \
  --victim_ip 192.168.1.100 \
  --attacker_ip 192.168.1.50
```

**警告：**
```
⚠️  ARP SPOOFING DETECTED

事件時間線:
[10:05:18.562] 正常 ARP: 192.168.1.1 → 00:11:22:33:44:55 (Gateway)
[10:05:45.781] 異常 ARP: 192.168.1.1 → AA:BB:CC:DD:EE:FF ❌
                         ^ 同一 IP，不同 MAC

威脅分析:
- Source MAC 00:11:22:33:44:66 (攻擊設備)
- MAC 變更次數: 5 (異常高)
- 可能目的: MITM (中間人攻擊)
```

### 演示所需 Python 工具

#### simulate_port_scan.py
```python
#!/usr/bin/env python3
import argparse
from scapy.all import *

def port_scan(target_ip, num_ports=100):
    """Simulate TCP port scanning"""
    for port in range(1024, 1024 + num_ports):
        pkt = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(pkt, verbose=0)
        print(f"[SYN] {target_ip}:{port}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--ports", type=int, default=100)
    args = parser.parse_args()
    
    port_scan(args.target, args.ports)
```

#### simulate_syn_flood.py
```python
#!/usr/bin/env python3
import argparse
import threading
from scapy.all import *

def syn_flood_worker(target_ip, target_port, rate_per_sec):
    """SYN 洪泛工作執行緒"""
    interval = 1.0 / rate_per_sec
    
    while True:
        src_port = RandShort()
        pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        send(pkt, verbose=0)
        
        time.sleep(interval)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--port", type=int, default=80)
    parser.add_argument("--rate", type=int, default=1000)
    parser.add_argument("--threads", type=int, default=4)
    args = parser.parse_args()
    
    rate_per_thread = args.rate // args.threads
    
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(
            target=syn_flood_worker,
            args=(args.target, args.port, rate_per_thread)
        )
        t.daemon = True
        t.start()
        threads.append(t)
    
    try:
        for t in threads:
            t.join()
    except KeyboardInterrupt:
        print("\n[*] SYN Flood 已停止")
```

### 完整演示時間軸

| 時間 | 操作 | 效果 |
|------|------|------|
| 00:00 - 00:30 | 啟動程式 | 系統就緒，開始監控 |
| 00:30 - 01:30 | 正常使用 | 展示實時統計、流量圖表 |
| 01:30 - 02:00 | Port Scanning | 即時偵測與警告 |
| 02:00 - 02:45 | SYN Flood | 關鍵指標闪爍，日誌密集輸出 |
| 02:45 - 03:05 | ARP Spoofing | 偵測並提示威脅分析 |
| 03:05 onwards | Q&A | 展示代碼、解答技術細節 |

### 項目成果物清單

展示以下文件/日誌：
```
├── /bin/
│   └── NetworkMonitor.exe                    # 最終可執行檔
│
├── /rules/
│   ├── custom.rules                         # 自訂 Snort 規則
│   └── default.rules                        # 內建規則庫
│
├── /logs/
│   ├── 2025-03-09_session_normal.json       # 正常流量日誌
│   ├── 2025-03-09_attack_port_scan.json     # 掃描警告日誌
│   ├── 2025-03-09_attack_syn_flood.json     # DDoS 日誌
│   └── 2025-03-09_attack_arp_spoof.json     # ARP 欺騙日誌
│
├── /docs/
│   ├── Architecture.md                      # 架構文檔
│   ├── API_Reference.md                     # API 文檔
│   └── Performance_Report.pdf               # 性能報告
│
├── /test/
│   ├── test_parser.cpp                      # 協定解析單元測試
│   ├── test_detection.cpp                   # 攻擊偵測單元測試
│   └── benchmark_results.txt                # 性能基準測試
│
└── /src/
    ├── main.cpp                             # 主程式進入點
    ├── NetworkMonitor.h/.cpp                # 核心監控類別
    ├── PacketCapture.h/.cpp                 # 擷取模組
    ├── ProtocolParser.h/.cpp                # 協定解析器
    ├── DetectionEngine.h/.cpp               # 攻擊偵測引擎
    ├── SnortRuleParser.h/.cpp               # Snort 規則解析
    ├── AlertHandler.h/.cpp                  # 警告系統
    └── RingBuffer.h/.cpp                    # 環形緩衝區
```

---

## 附錄：常見問題與最佳實踐

### Q1: 如何在 Windows 防火牆中測試捕獲？
```
Windows Defender Firewall
├─ 進階設定
├─ 輸入規則
└─ 新規則 → 允許埠 80, 443, 53 (用於測試)
```

### Q2: Npcap vs WinPcap 的差異？
- **WinPcap**: 舊版本，停止維護
- **Npcap**: 最新維護版，支援 Windows 10/11，效能更好

### Q3: 如何處理超高速網卡 (100 Gbps)?
- 使用 DPDK (Data Plane Development Kit)
- 或採用 NUMA-aware 多核心綁定

### Q4: 規則更新頻率？
建議每週更新一次 Snort 規則集，訂閱以下來源：
- Snort Community Rules (免費)
- Emerging Threats (ET)

---

**文檔版本:** v1.0  
**最後更新:** 2025 年 3 月 9 日  
**維護者:** Network Security Lab
