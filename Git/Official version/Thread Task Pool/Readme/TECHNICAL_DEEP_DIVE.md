# C++ 網路監控系統 - 技術深度指南與常見問題

## 目錄
1. [環境配置常見問題](#環境配置常見問題)
2. [協議解析技術深度](#協議解析技術深度)
3. [多執行緒設計最佳實踐](#多執行緒設計最佳實踐)
4. [攻擊偵測算法詳解](#攻擊偵測算法詳解)
5. [性能優化秘訣](#性能優化秘訣)
6. [debug 與測試](#debug-與測試)

---

## 環境配置常見問題

### Q1: Windows 上如何安裝 Npcap？

**步驟：**

1. **下載 Npcap**
   - 訪問 https://nmap.org/npcap/
   - 下載 `Npcap-1.70-oem.exe` 或最新版本

2. **安裝驅動**
   ```bash
   # 以管理員身份運行安裝程式
   Npcap-1.70-oem.exe
   
   # 選項：
   # ✓ Install Npcap OEM (個人使用)
   # ✓ Loopback 支援 (可選，用於測試)
   ```

3. **驗證安裝**
   ```cpp
   #include <pcap.h>
   
   int main() {
       char errbuf[PCAP_ERRBUF_SIZE];
       pcap_if_t* devices;
       
       if (pcap_findalldevs(&devices, errbuf) == 0) {
           printf("✓ Npcap 安裝成功\n");
       } else {
           printf("✗ 安裝失敗: %s\n", errbuf);
       }
       return 0;
   }
   ```

4. **權限設置**
   ```
   如果出現 "No such device exists" 錯誤:
   ① Windows 開始菜單 → 網路設定 → 變更進階網路設定
   ② 查找 "Npcap Loopback Adapter"
   ③ 確保狀態為 "已連接"
   ```

### Q2: Linux 上如何使用 libpcap？

**Ubuntu/Debian:**
```bash
# 安裝套件
sudo apt-get install libpcap-dev libpcap0.8 tcpdump

# 編譯時鏈接
g++ -o monitor main.cpp -lpcap

# 運行時可能需要 root 權限
sudo ./monitor
```

**Fedora/RHEL:**
```bash
sudo dnf install libpcap-devel tcpdump

# 或為用戶組授予權限（避免 root）
sudo usermod -a -G wireshark,pcap $USER
```

### Q3: 如何在 Visual Studio 中配置 Npcap SDK？

**方法 1：項目屬性配置**
```
1. 項目 → 屬性
2. VC++ 目錄
   - 包含目錄: C:\Npcap\Include
   - 庫目錄: C:\Npcap\Lib\x64

3. 連結器 → 輸入
   - 附加相依性: wpcap.lib ws2_32.lib iphlpapi.lib

4. 建立
```

**方法 2：CMakeLists.txt 配置**
```cmake
cmake_minimum_required(VERSION 3.10)
project(NetworkMonitor)

# Windows 特定配置
if(WIN32)
    set(PCAP_INCLUDE_DIR "C:/Npcap/Include")
    set(PCAP_LIBRARY "C:/Npcap/Lib/x64/wpcap.lib")
    
    add_definitions(-DWIN32 -D_WINDOWS)
    link_libraries(ws2_32 iphlpapi winsock2)
endif()

add_executable(monitor main.cpp)

target_include_directories(monitor PRIVATE ${PCAP_INCLUDE_DIR})
target_link_libraries(monitor PRIVATE ${PCAP_LIBRARY})
```

---

## 協議解析技術深度

### 理解網位元序 (Byte Order)

**背景：**
- **網絡字節序 (Network Byte Order)** = 大端 (Big-Endian)
- **主機字節序** = 小端 (Little-Endian) 在 x86/x64 上

**實際例子：**
```
IP 地址 192.168.1.1 在網路上傳輸為:
192 = 11000000 (第 0 字節)
168 = 10101000 (第 1 字節)
1   = 00000001 (第 2 字節)
1   = 00000001 (第 3 字節)

若直接讀取為 uint32_t:
0xC0A80101 (16 進制)

轉換為主機序後:
htonl(0xC0A80101) = 0x0101A8C0 = 1.1.168.192 ✗ 錯誤!

正確做法:
uint32_t raw = *(uint32_t*)packet;
uint32_t host_order = ntohl(raw);
// 結果正確
```

**快速轉換表：**
```cpp
// 網絡序 → 主機序
uint16_t port = ntohs(tcp_header->destination_port);
uint32_t ip = ntohl(ip_header->destination_ip);

// 主機序 → 網絡序
uint16_t net_port = htons(port);
uint32_t net_ip = htonl(ip);
```

### IPv4 標頭解析技巧

**問題：IHL (Internet Header Length) 是什麼？**
```
IPv4 標頭最少 20 字節（無選項）
最多 60 字節（15 * 4 字節）

IHL 字段存儲標頭長度 / 4

現實例子:
IHL = 5 → 標頭長度 = 5 * 4 = 20 字節 (無選項)
IHL = 7 → 標頭長度 = 7 * 4 = 28 字節 (8 字節選項)

正確跳過標頭:
offset += ihl * 4;  ✓ 正確
offset += 20;        ✗ 錯誤（可能丟失選項）
```

**TTL (Time To Live) 用途：**
```cpp
// 防止環路路由
// 每經過一個路由器，TTL 減 1
// TTL = 0 時丟棄封包

// 用途 1：檢測本地網路
if (ttl >= 64) return "遠程主機";  // TTL 通常從 64 開始
if (ttl >= 128) return "Windows 主機";
if (ttl >= 255) return "原始來源";

// 用途 2：偵測欺騙/異常
if (src_ip == local_network && ttl > 128) {
    ALERT("可能的 IP 欺騙");
}
```

### TCP Flags 詳解

```
TCP 標誌位 (按優先度):
┌─────────────────────────────┐
│ FLAGS 字節 (8 bits)         │
├─────────────────────────────┤
│ Bit 0 (LSB): FIN (結束)     │
│ Bit 1:       SYN (同步)     │
│ Bit 2:       RST (重設)     │
│ Bit 3:       PSH (推送)     │
│ Bit 4:       ACK (確認)     │
│ Bit 5:       URG (緊急)     │
│ Bit 6-7:     保留           │
└─────────────────────────────┘
```

**三向交握 (TCP Handshake) 序列：**
```
客戶端              服務器
  │                  │
  ├─ SYN (SEQ=100) ──→ ① SYN_RECEIVED
  │                  │
  ← SYN+ACK (SEQ=300, ACK=101) ─
  │                  │
  ├─ ACK (SEQ=101, ACK=301) ──→ ESTABLISHED
  │                  │
```

**常見組合識別：**
```cpp
#define TCP_SYN_ONLY()    (flags == 0x02)
#define TCP_SYN_ACK()     (flags == 0x12)
#define TCP_ACK_ONLY()    (flags == 0x10)
#define TCP_FIN_ACK()     (flags == 0x11)
#define TCP_RST()         (flags == 0x04)
#define TCP_PUSH_ACK()    (flags == 0x18)
```

---

## 多執行緒設計最佳實踐

### 避免死鎖 (Deadlock) 的 5 個原則

**原則 1：一致性的鎖順序**
```cpp
// ✗ 危險：不同線程以不同順序獲取鎖
Thread A:   lock(mutex1) → lock(mutex2)
Thread B:   lock(mutex2) → lock(mutex1)  // 可能死鎖!

// ✓ 正確：統一鎖順序
Thread A:   lock(mutex1) → lock(mutex2)
Thread B:   lock(mutex1) → lock(mutex2)  // 不會死鎖
```

**原則 2：最小化鎖持有時間**
```cpp
// ✗ 不好：鎖持有時間長
{
    std::lock_guard<std::mutex> lock(mtx);
    expensive_computation();  // 執行時間長
    io_operation();           // 網路 I/O
    database_query();         // 數據庫查詢
}

// ✓ 好：最小化鎖範圍
{
    std::lock_guard<std::mutex> lock(mtx);
    shared_data = expensive_computation_result;
}
// 後續操作在鎖外執行
io_operation();
database_query();
```

**原則 3：避免在鎖內呼叫外部函式**
```cpp
// ✗ 危險：不知道 external_func 是否會嘗試獲取其他鎖
{
    std::lock_guard<std::mutex> lock(mtx);
    some_data = external_func(some_data);  // 可能死鎖
}

// ✓ 好：先複製數據，在鎖外操作
std::string local_copy;
{
    std::lock_guard<std::mutex> lock(mtx);
    local_copy = some_data;
}
local_copy = external_func(local_copy);
```

**原則 4：使用 RAII 自動解鎖**
```cpp
// ✗ 容易出錯
void process_data() {
    mtx.lock();
    
    if (some_error) {
        return;  // ⚠️ 忘記解鎖!
    }
    
    // 處理數據
    mtx.unlock();
}

// ✓ 自動解鎖
void process_data() {
    std::lock_guard<std::mutex> lock(mtx);  // RAII
    
    if (some_error) {
        return;  // ✓ 自動解鎖
    }
    
    // 處理數據
}  // ✓ 自動解鎖
```

**原則 5：優先使用原子操作而非互斥體**
```cpp
// 統計計數器
class Statistics {
private:
    std::atomic<uint64_t> packet_count{0};  // ✓ 輕量
    std::atomic<uint64_t> byte_count{0};
    
public:
    void increment_packets(uint64_t delta) {
        packet_count.fetch_add(delta, std::memory_order_relaxed);
    }
    
    uint64_t get_packets() const {
        return packet_count.load(std::memory_order_acquire);
    }
};

// 為什麼比互斥體快？
// 互斥體: lock → 模式切換 → 上下文切換 (~1000 ns)
// 原子操作: CPU CAS 指令 (~10 ns)
```

### 條件變數的正確使用

```cpp
class PacketQueue {
private:
    std::queue<Packet> queue;
    std::mutex mtx;
    std::condition_variable cv;
    
public:
    // 生產者：推入數據
    void push(const Packet& pkt) {
        {
            std::unique_lock<std::mutex> lock(mtx);
            queue.push(pkt);
        }  // 先解鎖
        cv.notify_one();  // 再通知：避免驚群效應
    }
    
    // 消費者：等待數據
    bool wait_pop(Packet& pkt, int timeout_ms) {
        std::unique_lock<std::mutex> lock(mtx);
        
        // ✓ 使用 Lambda predicate 避免虛假喚醒
        bool has_data = cv.wait_for(
            lock,
            std::chrono::milliseconds(timeout_ms),
            [this] { return !queue.empty(); }
        );
        
        if (!has_data) return false;
        
        pkt = queue.front();
        queue.pop();
        return true;
    }
};

// 常見錯誤：不檢查條件
while (true) {
    cv.wait(lock);  // ✗ 虛假喚醒!
    process_item();
}

// 正確方式：循環檢查條件
while (queue.empty()) {
    cv.wait(lock);  // ✓ 正確
}
process_item();
```

---

## 攻擊偵測算法詳解

### SYN Flood 偵測 - 詳細算法

**背景理解：**
```
正常連接建立:
SYN 封包 (初始化連接)
SYN+ACK 回應 (服務器響應)
ACK 確認 (連接建立)
Data 交換

SYN Flood 攻擊:
大量 SYN 封包 ⟵ (攻擊者)
無 ACK 回應 ✗
連接表溢出 ⟶ 合法客戶端無法連接
```

**實作演算法：**

```cpp
class SynFloodDetector {
private:
    // 滑動時間窗口
    struct TimeWindow {
        uint32_t syn_count = 0;
        uint32_t ack_count = 0;
        std::chrono::steady_clock::time_point start_time;
    };
    
    std::map<std::string, TimeWindow> syn_stats;  // IP -> 統計
    const int WINDOW_SIZE_SEC = 1;
    const int SYN_THRESHOLD = 100;
    const float MIN_ACK_RATIO = 0.1;  // 至少 10% ACK
    
public:
    struct DetectionResult {
        bool is_attack = false;
        float confidence = 0.0;  // 0-100%
        std::string reason;
    };
    
    DetectionResult check(const PacketFeature& pkt) {
        DetectionResult result;
        
        if (!pkt.is_tcp()) return result;
        
        auto& window = syn_stats[pkt.src_ip];
        auto now = std::chrono::steady_clock::now();
        
        // 清空舊窗口
        if (std::chrono::duration_cast<std::chrono::seconds>(
            now - window.start_time).count() > WINDOW_SIZE_SEC) {
            window = TimeWindow{};
            window.start_time = now;
        }
        
        // 統計 SYN/ACK
        if (pkt.tcp_flags & TCPHeader::FLAG_SYN) {
            window.syn_count++;
        }
        if (pkt.tcp_flags & TCPHeader::FLAG_ACK) {
            window.ack_count++;
        }
        
        // 判斷攻擊
        if (window.syn_count >= SYN_THRESHOLD) {
            float ack_ratio = (float)window.ack_count / window.syn_count;
            
            if (ack_ratio < MIN_ACK_RATIO) {
                result.is_attack = true;
                result.confidence = std::min(99.0f, 
                    (1.0f - ack_ratio) * 100.0f);
                result.reason = "SYN:ACK ratio abnormal";
            }
        }
        
        return result;
    }
};
```

**調整閾值的方法：**
```cpp
// 不同應用場景的閾值

// 1. 高流量環境（互聯網主幹）
const int SYN_THRESHOLD = 10000;     // 高容忍度

// 2. 企業內網
const int SYN_THRESHOLD = 500;       // 中等容忍度

// 3. 小型服務（IoT）
const int SYN_THRESHOLD = 50;        // 低容忍度

// 動態基準學習
class AdaptiveThreshold {
private:
    std::deque<uint32_t> syn_history;
    const size_t LEARNING_SIZE = 300;  // 5 分鐘
    
public:
    int get_threshold() const {
        if (syn_history.size() < LEARNING_SIZE) {
            return DEFAULT_THRESHOLD;
        }
        
        // 計算平均值 + 標準差 * 3
        uint32_t sum = 0;
        for (auto v : syn_history) sum += v;
        uint32_t avg = sum / syn_history.size();
        
        // 計算標準差
        uint32_t variance = 0;
        for (auto v : syn_history) {
            variance += (v - avg) * (v - avg);
        }
        variance /= syn_history.size();
        uint32_t stddev = std::sqrt(variance);
        
        return avg + (3 * stddev);  // 只在異常時觸發
    }
};
```

### Port Scan 偵測 - 時間-埠號關聯

**檢测邏輯矩陣：**
```
典型掃描特徵:
時間軸 ──────→
  ↓ 埠號
  20   ● ●
  21   ● ●    ← 大量埠號快速訪問
  22   ● ●      = Port Scan
  23   ● ●
  80   ● ●
 443   ● ●
2222   ● ●
3306   ● ●

各種掃描類型識別:
- 頂部掃描 (Top Ports): 常見埠號短時間大量訪問
- 連續掃描 (Sequential): 1-1024 依次掃描
- 隨機掃描 (Random): 完全隨機埠號
```

**實作代碼：**
```cpp
class PortScanDetector {
private:
    // 聯繫建立狀態
    enum ConnectionState {
        ESTABLISHED,      // 成功建立
        HALF_OPEN,        // SYN 已發送
        REJECTED,         // RST 接收
        TIMEOUT           // 無回應
    };
    
    struct PortInfo {
        ConnectionState state;
        std::chrono::steady_clock::time_point timestamp;
    };
    
    // IP -> (Port -> PortInfo)
    std::map<std::string, std::map<uint16_t, PortInfo>> port_matrix;
    
    const int SCAN_THRESHOLD = 20;
    const int TIME_WINDOW_SEC = 5;
    
public:
    bool is_port_scan(const std::string& src_ip) {
        auto& ports = port_matrix[src_ip];
        
        // 清理舊條目
        auto now = std::chrono::steady_clock::now();
        for (auto it = ports.begin(); it != ports.end(); ) {
            if (std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.timestamp).count() > TIME_WINDOW_SEC) {
                it = ports.erase(it);
            } else {
                ++it;
            }
        }
        
        // 計算不同狀態的埠號數
        int syn_sent = 0, rejected = 0;
        for (auto& [port, info] : ports) {
            if (info.state == HALF_OPEN) syn_sent++;
            if (info.state == REJECTED) rejected++;
        }
        
        // Port Scan 特徵：大量半開連接或拒絕
        if ((syn_sent + rejected) >= SCAN_THRESHOLD) {
            return true;
        }
        
        return false;
    }
};
```

### ARP Spoofing 偵測 - MAC-IP 對應驗證

**基本原理：**
```
正常 ARP:
IP 192.168.1.1 → MAC 00:11:22:33:44:55
(一個 IP 對應一個 MAC)

ARP Spoofing:
IP 192.168.1.1 → MAC 00:11:22:33:44:55
IP 192.168.1.1 → MAC AA:BB:CC:DD:EE:FF  ← 欺騙!
(同一 IP，多個 MAC)
```

**實作代碼：**
```cpp
class ARPSpoofingDetector {
private:
    // IP -> 檢測到的 MAC 集合
    std::map<std::string, std::set<std::string>> local_arp_table;
    
    // 系統級別的 ARP 表（用於驗證）
    std::map<std::string, std::string> system_arp_cache;
    
    const int MAX_MACS_PER_IP = 1;  // 正常情況下 1 MAC
    const int SPOOFING_CHANGE_THRESHOLD = 3;  // 3 次改變視為欺騙
    
public:
    bool check_arp(const std::string& ip, const std::string& mac) {
        auto& macs = local_arp_table[ip];
        
        if (macs.find(mac) == macs.end()) {
            macs.insert(mac);
        }
        
        // 檢測 1：多 MAC 綁定
        if (macs.size() > MAX_MACS_PER_IP) {
            ALERT("ARP Spoofing: Multiple MACs for IP " + ip);
            return true;
        }
        
        // 檢測 2：與系統 ARP 表不符
        if (system_arp_cache.count(ip) && 
            system_arp_cache[ip] != mac) {
            ALERT("ARP Spoofing: MAC mismatch for IP " + ip);
            return true;
        }
        
        return false;
    }
    
    void update_system_arp() {
        // 實作方式：讀取 ARP 表
        // Windows: arp -a
        // Linux: cat /proc/net/arp
        
        // 簡化版本
        system_arp_cache["192.168.1.1"] = "00:11:22:33:44:55";
    }
};
```

---

## 性能優化秘訣

### 優化 1：使用 mmap 代替反復銷毀的內存分配

**問題：**
```
標准方法: new Buffer() → delete Buffer()
成本: 系統呼叫 2 次 + 堆碎片化

高頻率情況下 (100K pps):
= 100,000 個 new/delete 操作/秒
= 嚴重的緩存抖動
```

**解決方案：預分配內存池**
```cpp
class FixedMemoryPool {
private:
    struct Block {
        uint8_t data[2048];  // 最大 MTU
        bool in_use = false;
    };
    
    std::vector<Block> pool;
    std::stack<Block*> free_blocks;
    std::mutex pool_mutex;
    
public:
    FixedMemoryPool(size_t pool_size) : pool(pool_size) {
        for (auto& block : pool) {
            free_blocks.push(&block);
        }
    }
    
    uint8_t* allocate() {
        std::lock_guard<std::mutex> lock(pool_mutex);
        
        if (free_blocks.empty()) {
            return nullptr;  // 池滿，需要等待
        }
        
        Block* block = free_blocks.top();
        free_blocks.pop();
        block->in_use = true;
        return block->data;
    }
    
    void deallocate(uint8_t* ptr) {
        std::lock_guard<std::mutex> lock(pool_mutex);
        
        Block* block = reinterpret_cast<Block*>(
            (uintptr_t)ptr - offsetof(Block, data)
        );
        block->in_use = false;
        free_blocks.push(block);
    }
};

// 使用
auto* buffer = pool.allocate();
// 處理...
pool.deallocate(buffer);
```

### 優化 2：SIMD 加速協議解析

**使用 SSE/AVX 快速掃描標誌位：**
```cpp
// 標準方式（逐個檢查）
for (int i = 0; i < pkt_len; i++) {
    if (data[i] == '\r' && data[i+1] == '\n') {
        // 找到行尾
    }
}

// SIMD 加速（搜索多個字節）
#ifdef __SSE4_2__
    #include <nmmintrin.h>
    
    __m128i needle = _mm_setr_epi8(
        '\r', '\n', 0, 0,  // 搜索 "\r\n"
        0, 0, 0, 0,
        0, 0, 0, 0,
        0, 0, 0, 0
    );
    
    // 每 16 字節並行檢查
    __m128i haystack = _mm_loadu_si128((__m128i*)data);
    int found = _mm_cmpestri(needle, 2, haystack, pkt_len, _SIDD_UBYTE_OPS);
#endif

// 性能提升：4-8 倍
```

### 優化 3：批量處理而非逐個處理

**不好的方式：**
```cpp
while (true) {
    Packet pkt = pcap->get_packet();     // 單個
    if (!pkt) break;
    
    process_packet(pkt);                  // 單個處理
    update_stats(pkt);                    // 單個更新
}

// 缺點：
// - CPU 快取命中率低
// - 分支預測失敗多
// - 內存帶寬浪費
```

**好的方式：批量處理**
```cpp
const size_t BATCH_SIZE = 64;  // 一次處理 64 個封包

while (true) {
    std::vector<Packet> batch = pcap->get_batch(BATCH_SIZE);
    if (batch.empty()) break;
    
    // 批量操作：一次性更新統計、規則比對等
    for (const auto& pkt : batch) {
        extract_features(pkt);
    }
    
    for (const auto& pkt : batch) {
        check_rules(pkt);
    }
    
    for (const auto& pkt : batch) {
        update_stats(pkt);
    }
}

// 優勢：
// - 相同類型操作連續執行 → 快取命中率 ↑
// - 分支少 → 預測準確率 ↑
// - 並行性更強 → SIMD 優化機會
```

### 優化 4：避免虛擬函式呼叫的開銷

**問題：虛擬函式有間接尋址成本**
```cpp
// ✗ 虛擬函式（經常呼叫）
class Detector {
public:
    virtual bool check(const Packet& pkt) = 0;  // 多態
};

DetectionEngine engine;
for (const auto& pkt : packets) {
    if (engine.check(pkt)) {  // 每次都進行虛擬尋址
        // ...
    }
}

// 成本分析：
// - L1 快取命中失敗：取 vtable 指針 (~40 cycles)
// - 分支預測失敗：跳轉地址不確定 (~20 cycles)
// 100K pps × 60 cycles ≈ 6 GHz 頻率滿載

// ✓ 模板（編譯時多態）
template<typename Detector>
void detect_packets(const std::vector<Packet>& packets) {
    Detector detector;
    for (const auto& pkt : packets) {
        if (detector.check(pkt)) {  // 內聯，無間接尋址
            // ...
        }
    }
}
```

---

## debug 與測試

### 使用 Wireshark 對比驗證

**與軟體對比：**
```bash
# 1. 啟動 Wireshark 捕獲
wireshark -i eth0 -w capture.pcap

# 2. 同時運行自己的監控程式
./network_monitor

# 3. 停止後，用 Wireshark 打開 capture.pcap
wireshark capture.pcap

# 4. 對比輸出
# 你的軟體: Source IP = 192.168.1.100
# Wireshark: Source IP = 192.168.1.100
# ✓ 匹配
```

### 使用 ThreadSanitizer 檢測競態條件

**編譯選項：**
```bash
# GCC/Clang
g++ -fsanitize=thread -g main.cpp -o monitor

# 運行時檢測
./monitor
# 輸出:
# WARNING: ThreadSanitizer: data race
# ...
```

### 使用 Valgrind 檢測記憶體洩漏

```bash
# 檢測洩漏
valgrind --leak-check=full --show-leak-kinds=all \
         ./monitor 2>&1 | tee valgrind.log

# 檢查輸出
grep "LEAK SUMMARY" valgrind.log
```

### 性能基準測試

```cpp
#include <chrono>

void benchmark_parser() {
    // 準備 10000 個真實封包
    std::vector<uint8_t> packet_data = load_pcap("test.pcap");
    
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < 100000; i++) {
        PacketFeature feature = ProtocolParser::parse_packet(
            packet_data.data(), packet_data.size()
        );
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(
        end - start
    );
    
    double ns_per_packet = duration.count() / 100000.0;
    double packets_per_sec = 1e9 / ns_per_packet;
    
    std::cout << "解析速度: " << packets_per_sec / 1e6 << " Mpps" << std::endl;
    // 預期: > 1 Mpps (百萬封包/秒)
}
```

---

## 附錄：命令速查表

### Windows

```bash
# 列出網卡
getmac /s %computername%
wmic nic get name,macaddress

# 查看 ARP 表
arp -a

# 監控網路流量
netstat -an | findstr ESTABLISHED

# tcpdump 對應物
WinDump -i 1 -w capture.pcap
```

### Linux

```bash
# 列出網卡
ip link show
ifconfig

# 列出網卡 IP
ip addr show
hostname -I

# 查看 ARP 表
ip neigh show
cat /proc/net/arp

# tcpdump 抓包
sudo tcpdump -i eth0 -w capture.pcap

# 分析 pcap 檔
tcpdump -r capture.pcap | head -20
```

---

**文檔版本:** v1.0  
**最後更新:** 2025 年 3 月 9 日
