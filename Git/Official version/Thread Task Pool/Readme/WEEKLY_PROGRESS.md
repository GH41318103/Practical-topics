# C++ 網路監控專題 - 周進度快速參考

## Week 1: 環境與基礎 (共 5 天)

### 💻 開發環境
- [ ] 安裝 Visual Studio 2022 (C++17 以上)
- [ ] 下載並安裝 Npcap SDK v1.3+
- [ ] 配置 VS 編譯環境 (Include、Lib、Link)
- [ ] 測試編譯環境

### 📝 代碼交付物
```
src/
├── list_devices.cpp          ✓ 列出網卡
├── simple_capture.cpp        ✓ 基本抓包
└── CMakeLists.txt            ✓ 構建配置
```

### 🎯 驗收標準
- ✓ 程式能列出現有網卡信息（名稱、描述）
- ✓ 能從選定網卡成功抓取至少 100 個封包
- ✓ 打印每個封包的基本信息（長度、時間戳）
- ✓ 無編譯 Warning

### 📚 參考資源
- Npcap 官方文檔：https://nmap.org/npcap/
- WinPcap 教程：http://www.tcpdump.org/papers/sniffing-faq.html

---

## Week 2: 協定解析層 (共 5 天)

### 🔧 技術重點
- [ ] 實作 Ethernet 標頭解析
- [ ] 實作 IPv4/IPv6 標頭解析
- [ ] 實作 TCP/UDP 標頭解析
- [ ] 支援 ICMP、DNS、ARP 協議

### 📝 代碼交付物
```
src/
├── ProtocolHeaders.h         ✓ 協議結構定義
├── ProtocolParser.h/.cpp     ✓ 解析邏輯
├── packet_analyzer.cpp       ✓ 主程序
└── test/
    └── test_parser.cpp       ✓ 單元測試
```

### 🎯 驗收標準
- ✓ 能正確解析 Ethernet、IPv4、TCP 標頭
- ✓ 提取源/目的 IP、Port、協議類型
- ✓ 識別 TCP Flags (SYN, ACK, FIN 等)
- ✓ 處理分片封包（Fragmented）

### 📊 測試方法
```bash
# 使用 Wireshark 對比驗證
ping google.com              # ICMP
curl https://google.com      # TCP/HTTPS
nslookup google.com          # DNS/UDP
```

---

## Week 3: 核心架構架設 (共 5 天)

### 🏗️ 技術重點
- [ ] 設計並實作 Ring Buffer
- [ ] 實現多執行緒架構 (Capture + Analysis)
- [ ] 執行緒同步 (Mutex, Condition Variable)
- [ ] 性能基準測試

### 📝 代碼交付物
```
src/
├── RingBuffer.h/.cpp         ✓ 環形緩衝區
├── NetworkMonitor.h/.cpp     ✓ 核心監控類
├── thread_test.cpp           ✓ 多執行緒測試
└── benchmark/
    └── performance.cpp       ✓ 性能基準測試
```

### 🎯 驗收標準
- ✓ Ring Buffer 容量 >= 10,000 個封包
- ✓ Capture 執行緒穩定執行，無卡頓
- ✓ Analysis 執行緒不被 Capture 阻塞
- ✓ 無記憶體洩漏（valgrind/Dr.Memory 驗證）
- ✓ 在 100K pps 下保持 < 10% CPU

### 📊 性能目標
| 指標 | 目標 | 實現 |
|------|------|------|
| 吞吐量 | > 100K pps | - |
| 延遲 | < 1 ms | - |
| CPU 使用率 | < 15% | - |
| 記憶體 | < 200 MB | - |

---

## Week 4: 預處理引擎 (共 5 天)

### 📊 技術重點
- [ ] 實作流量統計模組
- [ ] 特徵提取（TTL、Payload、Flags）
- [ ] 按 IP/Port 計數
- [ ] 實時 Mbps、PPS 計算

### 📝 代碼交付物
```
src/
├── Statistics.h/.cpp         ✓ 統計模組
├── FeatureExtractor.h/.cpp   ✓ 特徵提取
├── TrafficCalculator.h/.cpp  ✓ 流量計算
└── test/
    └── test_statistics.cpp   ✓ 統計單元測試
```

### 🎯 驗收標準
- ✓ 能動態追蹤前 100 個活躍 IP
- ✓ 每秒更新一次統計數據
- ✓ 計算準確度 > 99%
- ✓ UI 顯示 Top 10 流量來源

### 📈 統計示例輸出
```
=== 流量統計 (更新時間: 10:45:23.456) ===
總計封包:      1,234,567
總計字節:      2.34 GB
上傳速度:      234.5 Mbps (↑)
下載速度:      567.8 Mbps (↓)

Top 5 IP:
  1. 192.168.1.100    345.2 Mbps  (Chrome)
  2. 192.168.1.101    234.1 Mbps  (Windows Update)
  3. 8.8.8.8          45.3 Mbps   (DNS/Google)
  4. 172.217.14.206   23.4 Mbps   (YouTube)
  5. 142.251.41.14    12.1 Mbps   (Meta CDN)
```

---

## Week 5: 偵測邏輯實作 (共 5 天)

### 🛡️ 技術重點
- [ ] SYN Flood 偵測演算法
- [ ] Port Scanning 偵測演算法
- [ ] ARP Spoofing 偵測演算法
- [ ] 靜態規則引擎

### 📝 代碼交付物
```
src/
├── DetectionEngine.h/.cpp    ✓ 偵測核心
├── attacks/
│   ├── SynFloodDetector.h/.cpp    ✓ SYN 洪泛
│   ├── PortScanDetector.h/.cpp    ✓ 埠口掃描
│   └── ArpSpoofDetector.h/.cpp    ✓ ARP 欺騙
└── test/
    └── test_detection.cpp    ✓ 偵測單元測試
```

### 🎯 驗收標準
- ✓ SYN Flood：100 SYN/sec 觸發警報，準確率 > 95%
- ✓ Port Scan：20 個不同 Port/5sec 觸發，準確率 > 90%
- ✓ ARP Spoofing：多 MAC for IP 立即偵測
- ✓ 0 false positive 在正常流量

### 📋 測試場景

#### SYN Flood 測試
```bash
# 攻擊腳本
python3 simulate_syn_flood.py \
  --target 192.168.1.100 \
  --port 80 \
  --rate 500

# 預期: 軟體在 2-3 秒內觸發警報
```

#### Port Scan 測試
```bash
nmap -sS -p1-1000 192.168.1.100
# 預期: 軟體在掃描過程中標記為異常流量
```

#### ARP Spoofing 測試
```bash
# 使用 Scapy 發送假 ARP 回應
python3 simulate_arp_spoofing.py
# 預期: 軟體檢測到 IP-MAC 對應不匹配
```

---

## Week 6: 進階功能 - Snort 規則解析 (共 5 天)

### 🔍 技術重點
- [ ] 實作 Snort 規則格式解析
- [ ] 支援基本 options (msg, sid, content)
- [ ] 動態規則載入
- [ ] 規則版本管理

### 📝 代碼交付物
```
src/
├── SnortRuleParser.h/.cpp    ✓ 規則解析器
├── RuleEngine.h/.cpp         ✓ 規則執行引擎
├── RuleManager.h/.cpp        ✓ 規則管理員
└── test/
    └── test_snort_rules.cpp  ✓ 規則解析測試

rules/
├── custom.rules              ✓ 自訂規則
└── default.rules             ✓ 預設規則庫
```

### 🎯 驗收標準
- ✓ 能解析標準 Snort 規則格式
- ✓ 支援加載 .rules 檔案
- ✓ 規則錯誤無損程式運行
- ✓ 動態新增規則無需重編譯

### 📋 規則範例測試
```snort
# 測試規則 1: HTTP Flood
alert tcp $EXTERNAL_NET any -> $HOME_NET 80 \
  (msg:"HTTP Flood Attempt"; \
   threshold: type both, track by_src, count 100, seconds 1; \
   sid:3000001; rev:1;)

# 測試規則 2: DNS Query Flood
alert dns $EXTERNAL_NET any -> $HOME_NET 53 \
  (msg:"DNS Query Flood"; \
   threshold: type both, track by_src, count 50, seconds 5; \
   sid:3000002; rev:1;)
```

---

## Week 7: 告警與介面 (共 5 天)

### 🖥️ 技術重點
- [ ] 實作告警模組（日誌、通知、UI）
- [ ] JSON 格式日誌記錄
- [ ] CLI 圖表渲染
- [ ] 系統托盤通知

### 📝 代碼交付物
```
src/
├── AlertHandler.h/.cpp       ✓ 告警處理
├── Logger.h/.cpp             ✓ 日誌系統
├── Dashboard.h/.cpp          ✓ CLI 儀表板
├── Notifier.h/.cpp           ✓ 系統通知
└── test/
    └── test_ui.cpp           ✓ 介面測試

logs/
├── monitor_2025-03-09.json   ✓ 日誌檔
└── alerts_2025-03-09.json    ✓ 警告日誌
```

### 🎯 驗收標準
- ✓ 攻擊事件立即記錄為 JSON
- ✓ CLI 儀表板每秒更新
- ✓ 嚴重警報彈出系統通知
- ✓ 日誌可被外部工具解析（如 ELK Stack）

### 📊 UI 輸出示例
```
╔════════════════ NETWORK MONITOR ════════════════╗
║  Total Packets: 1.2M/sec                        ║
║  Upstream: 234.5 Mbps (↑)                       ║
║  Downstream: 567.8 Mbps (↓)                     ║
║                                                  ║
║  Top Threats:                                   ║
║  ⚠️  Port Scan (203.0.113.50)  - 73 ports     ║
║  ⚠️  SYN Flood (198.51.100.10)  - 5K/sec      ║
║  ⚠️  ARP Spoofing (192.168.1.X) - 3 events    ║
╚══════════════════════════════════════════════════╝
```

---

## Week 8: 測試與演示 (共 5 天)

### 🧪 技術重點
- [ ] 完整壓力測試
- [ ] 準確度驗證
- [ ] 性能優化最後調整
- [ ] 演示腳本準備

### 📝 代碼交付物
```
test/
├── stress_test.cpp           ✓ 壓力測試
├── accuracy_test.cpp         ✓ 準確度測試
├── simulation/
│   ├── syn_flood.py          ✓ SYN 洪泛模擬
│   ├── port_scan.py          ✓ 埠口掃描模擬
│   └── arp_spoofing.py       ✓ ARP 欺騙模擬
└── reports/
    ├── performance_report.txt ✓ 性能報告
    └── test_results.json     ✓ 測試結果
```

### 🎯 驗收標準
- ✓ 100K pps 下維持穩定運行
- ✓ 攻擊偵測準確率 > 95%
- ✓ False positive < 1%
- ✓ 完整演示視頻 (5-10分鐘)

### 🎬 演示時間軸
| 時間 | 內容 | 著重點 |
|------|------|--------|
| 0:00-0:30 | 程式啟動與環境 | 展示穩定性 |
| 0:30-1:30 | 正常流量監控 | 實時統計、Top 10 IP |
| 1:30-2:00 | Port Scanning 攻擊 | 即時偵測、警告視覺化 |
| 2:00-2:45 | SYN Flood DDoS | 高流量下的反應 |
| 2:45-3:05 | ARP Spoofing | 特徵與威脅分析 |
| 3:05+ | Q&A | 技術細節解說 |

---

## 📅 全體進度追蹤

```
Week 1 ███░░░░░░ 基礎搭建完成 (60%)
Week 2 ████░░░░░ 協議解析進行中
Week 3 ░░░░░░░░░ 架構設計待展開
Week 4 ░░░░░░░░░ 統計模組待開發
Week 5 ░░░░░░░░░ 偵測引擎待實作
Week 6 ░░░░░░░░░ 進階功能待設計
Week 7 ░░░░░░░░░ UI 介面待完成
Week 8 ░░░░░░░░░ 測試與優化待進行
```

---

## ⚠️ 常見風險與對策

### 風險 1: 記憶體洩漏（High）
**對策:**
- 每周執行 Valgrind 或 DrMemory
- 使用 RAII 原則（Smart Pointer）
- 監控堆記憶體大小

### 風險 2: 執行緒死鎖（High）
**對策:**
- 使用 ThreadSanitizer 檢測
- 限制鎖持有時間
- 遵循鎖順序規則

### 風險 3: 高流量下丟包（Medium）
**對策:**
- 增加 Ring Buffer 容量
- 優化協議解析速度
- 使用 NUMA 感知優化

### 風險 4: 規則誤報（Medium）
**對策:**
- 建立 baseline 學習期（1 小時）
- 調整動態閾值
- 交叉驗證多個指標

---

## 📚 推薦學習資源

### 基礎知識
- [ ] TCP/IP 協議 (RFC 791, 793)
- [ ] Wireshark 使用教程
- [ ] C++ 多執行緒編程

### 高級主題
- [ ] Snort IDS 規則語法
- [ ] 入侵檢測基礎
- [ ] 網路安全最佳實踐

### 開發工具
- [ ] Git 版本控制
- [ ] CMake 構建系統
- [ ] GDB 除錯工具

---

**最後更新:** 2025-03-09  
**預期完成:** 2025-05-31 (8 週)
