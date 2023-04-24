/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

// 簡單的 L3 網絡轉發功能，
// 可以解析以太網幀和 IPv4 數據包頭部，進行基於最長前綴匹配(longest prefix match)的路由選擇，然後將包轉發出去。

// With IPv4 forwarding, the switch must perform the following actions for every packet: 
// (1) update the source and destination MAC addresses
// (2) decrement the time-to-live (TTL) in the IP header
// (3) forward the packet out the appropriate port

/*
1. 更新源和目標 MAC 地址：
在 MyIngress control 中，當 IPv4 header 被解析並且判斷出是有效的後，
會套用 ipv4_lpm table 中的 actions，其中的 ipv4_forward action 
會更新 Ethernet header 的 srcAddr 和 dstAddr。

2. 減少 IP header 的 TTL：
同樣在 MyIngress control 中，ipv4_forward action 也會對 IPv4 header 的 ttl 域進行減 1 的操作。

3. 轉發封包至適當的端口：
ipv4_lpm table 中的 ipv4_forward action 會將封包轉發到 
standard_metadata.egress_spec 指定的 egress port 上。
*/

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

// _t 代表 type，表示這些變數是自定義的型別

typedef bit<9>  egressSpec_t; // 出口規格，這裡用來當作 egress port ID
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*** 這裡定義了一個解析器 MyParser，用於將收到的包進行解析，並提取出包頭。
*** 解析器由三個部分組成： 1. 解析狀態機 2. 包頭提取操作 3. 狀態轉移語句。
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    // state start {
    //     /* TODO: add parser logic */
    //     transition accept;
    // }

    // 1. 解析器首先進入 start state，然後轉移到 parse_ethernet 狀態。
    state start {
        transition parse_ethernet;
    }
    // 2. 在 parse_ethernet state 中，
    state parse_ethernet {
        // 解析器提取以太網幀 header
        packet.extract(hdr.ethernet);
        // 並通過 select 語句判斷是否為 IPv4 數據包。
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;  // 如果是 IPv4 數據包，則轉移到 parse_ipv4 狀態
            default: accept;
        }
    }
    // 3. 在 parse_ipv4 state 中，
    state parse_ipv4 {
        // 提取 IPv4 數據包頭部。
        packet.extract(hdr.ipv4);
        // 最後，解析器轉移到 accept 狀態，結束解析。
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
該區塊定義了 MyVerifyChecksum 控制器，它是一個空操作（empty action）控制器。
在 P4 程式中，網絡協議通常包含一個檢查和（checksum）字段，用於檢測數據是否在傳輸過程中被修改。
在這裡，MyVerifyChecksum 控制器的作用是確保接收到的封包的檢查和字段的值是正確的。
如果檢查和不正確，則該控制器可以選擇丟棄封包或採取其他行動。
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
MyIngress 控制器(control)定義了 P4 程式的關鍵功能：如何處理接收到的封包。
該控制器定義了 ipv4_lpm table 和幾個 actions。

當一個接收到的封包進入到交換機的入口端口時，MyParser 解析器將會解析封包並生成一個包含數據的 headers 結構。
然後，MyIngress 控制器將使用這些數據來判斷如何處理封包。
在這種情況下，如果封包是一個 IPv4 封包，ipv4_lpm 表將被應用來決定下一步的操作。
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        // Sets the egress port for the next hop
        standard_metadata.egress_spec = port;
        // Updates the ethernet source address with the address of the switch.
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        // Updates the ethernet destination address with the address of the next hop.
        hdr.ethernet.dstAddr = dstAddr;
        // Decrement the time-to-live (TTL) in the IP header
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        // 表 ipv4_lpm 包含一個名為 key 的關鍵字段，即 IPv4 目的地址。
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        // 當 ipv4_lpm 表被應用時，它將尋找一個最長前綴匹配（longest prefix match）的鍵值，並且選擇與之相對應的動作。
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        // 如果沒有匹配的鍵，則預設情況下封包將被丟棄。
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()) { // ipv4_lpm should be applied only when IPv4 header is valid
            ipv4_lpm.apply();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
主要用於在封包轉發過程中計算和更新 IP 首部的檢查和（checksum），以確保封包在轉發過程中沒有被修改或損壞。
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
        // MyComputeChecksum 使用 update_checksum 函數更新 IP 標頭中的校驗和。
        update_checksum(
            hdr.ipv4.isValid(), // 表示該封包是否包含 IP 首部
            { hdr.ipv4.version, // {...} 這些字段將被用於計算檢查和
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,  // 這是 IP 首部中的檢查和字段，通過該函數計算後，會更新此字段。
            HashAlgorithm.csum16); // 表示使用的計算方法是 16 位檢查和算法
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
採用 MyDeparser() 控制器將傳出數據包的頭部解析成字節流。
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 使用 emit() 函数將 header 附加到 packet_out 數據包中。
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
最後一個控制器 V1Switch() 定義了一個交換機，它包含了所有我們之前定義的控制器，作為交換機流水線的各個階段。
在這個控制器中，我們使用 MyParser() 解析傳入的數據包，
然後使用 MyVerifyChecksum() 驗證數據包的檢查和，
進行 MyIngress() 進行入站處理，
然後使用 MyEgress() 進行出站處理，
再使用 MyComputeChecksum() 計算新的檢查和，
最後使用 MyDeparser() 將頭部解析為字節流。
*************************************************************************/

V1Switch(
MyParser(),          // 解析傳入的數據包，
MyVerifyChecksum(),  // 驗證數據包的檢查和
MyIngress(),         // 進行入站處理
MyEgress(),          // 進行出站處理
MyComputeChecksum(), // 計算新的檢查和
MyDeparser()         // 將頭部解析為字節流
) main;
