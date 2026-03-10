#include <pcap.h>      // Npcap 的核心標頭檔，提供抓包函式
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>

// 告訴連結器 (Linker) 去哪裡找實作功能的二進位檔案 (.lib)
#pragma comment(lib, "wpcap.lib")   // Npcap 的主要函式庫
#pragma comment(lib, "ws2_32.lib")  // Windows Socket 函式庫

int main() {
    // errbuf: 用於存放 Npcap 函式執行失敗時的錯誤訊息字串
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // alldevs: 指向網卡資訊鏈結串列 (Linked List) 頭部的指標
    pcap_if_t *alldevs;

    // --- 1. 列出網卡 (W1 功能) ---
    // pcap_findalldevs: 向 Npcap 驅動程式請求當前系統所有可用的網卡清單
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "列出網卡失敗: " << errbuf << std::endl;
        return 1;
    }

    // 使用 vector 暫存網卡指標，方便後續透過索引 (Index) 選取
    std::vector<pcap_if_t*> devList;
    int i = 0;
    
    // 遍歷鏈結串列，印出每張網卡的名稱與描述 (例如: Wi-Fi 6, Ethernet)
    for (pcap_if_t *d = alldevs; d != NULL; d = d->next) {
        std::cout << "[" << i++ << "] " << (d->description ? d->description : d->name) << std::endl;
        devList.push_back(d);
    }

    if (devList.empty()) {
        std::cout << "找不到任何網卡，請確保以管理員權限執行。" << std::endl;
        return 0;
    }

    int choice;
    std::cout << "請選擇網卡編號進行抓包: ";
    std::cin >> choice;

    // --- 2. 開啟網卡 (W1 功能) ---
    // pcap_open_live: 將選定的網卡切換至「監聽模式」
    // 參數解析:
    // devList[choice]->name: 網卡的系統內部名稱
    // 65536: 抓取封包的最大長度 (Snapshot Length)
    // 1: 開啟「混雜模式」(Promiscuous Mode)，抓取所有經過網卡的流量而不僅是發給自己的
    // 1000: 讀取逾時時間 (Timeout) 設定為 1000 毫秒
    pcap_t *adhandle = pcap_open_live(devList[choice]->name, 65536, 1, 1000, errbuf);
    
    if (adhandle == NULL) {
        std::cerr << "無法開啟網卡: " << devList[choice]->name << std::endl;
        pcap_freealldevs(alldevs); // 開啟失敗也需釋放清單記憶體
        return 1;
    }

    std::cout << "\n開始抓包... 按 Ctrl+C 停止\n" << std::endl;

    // --- 3. 基本抓包與打印 (W1 功能) ---
    // header: 存放封包的「中繼資料」(包含時間戳記、封包實際長度)
    struct pcap_pkthdr *header;
    // pkt_data: 指向記憶體中「原始二進位數據」的指標 (這是我們分析的對象)
    const u_char *pkt_data;
    int res;

    // pcap_next_ex: 從驅動程式的緩衝區讀取下一個封包
    // res == 1: 成功抓到封包
    // res == 0: 超時 (Timeout)，此段時間內沒有封包經過
    while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
        if (res == 0) continue; 

        // 印出抓到封包的時間 (秒.微秒) 與總長度 (Byte)
        printf("時間: %ld.%06ld 長度: %d 字節\n", header->ts.tv_sec, header->ts.tv_usec, header->len);

        // 打印前 16 個字節的十六進位 (Hex Dump)
        // 這些原始數據通常前 14 Byte 是 Ethernet Header，接著是 IP Header
        for (int j = 0; j < (header->len > 16 ? 16 : header->len); j++) {
            printf("%02x ", pkt_data[j]);
        }
        printf("...\n--------------------------------\n");
    }

    // --- 4. 清理資源 ---
    // 釋放先前由 pcap_findalldevs 分配的網卡清單記憶體
    pcap_freealldevs(alldevs);
    // 關閉網卡監聽控制把手
    pcap_close(adhandle);
    
    return 0;
}

/*
重點原理圖解
    1.記憶體映射 (Memory Mapping):
        當 pcap_next_ex 回傳 1 時，pkt_data 指向的是 Npcap 驅動程式內部緩衝區的一塊地址。這塊數據是原始的 (Raw)，包含了從資料連結層（Layer 2, Ethernet）開始的所有位元。

    2.混雜模式 (Promiscuous Mode):
        在 pcap_open_live 的第三個參數設為 1。這會告訴網卡：「不要丟掉那些目標 MAC 地址不是我的封包，請全部傳給我的程式」。這是 Sniffer 能抓到同區域網路其他電腦流量的關鍵。

    3.封包結構 (Packet Structure):
        你在 printf 看到的 02x 數據，實際上遵循以下結構：
            - Byte 0-5: 目的地的 MAC 地址
            - Byte 6-11: 來源地的 MAC 地址
            - Byte 12-13: 協定類型 (例如 08 00 代表 IPv4)
*/