#include <core.p4>
#include <ebpf_model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_ICMP = 0x01;

header Ethernet {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header IPv4 {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      totalLen;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    bit<32>      srcAddr;
    bit<32>      dstAddr;
}

header ICMP {
    bit<8>      type;
    bit<8>      code;
    bit<16>     checksum;
    bit<32>     icmp_header;
}


struct Headers_t {
    Ethernet ethernet;
    IPv4     ip;
    ICMP     icmp;
}

parser prs(packet_in p, out Headers_t headers) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        p.extract(headers.ethernet);
        transition select (headers.ethernet.etherType) {
            TYPE_IPV4 : parse_ip;
            default   : accept;
        }
    }

    state parse_ip {
        p.extract(headers.ip);
        transition select (headers.ip.protocol) {
            TYPE_ICMP : parse_icmp;
            default   : accept;
        }
    }

    state parse_icmp {
        p.extract(headers.icmp);
        transition accept;
    }
}

control pipe(inout Headers_t headers, out bool pass) {
    // action Reject(bool rej) {
    //     pass = rej;
    // }

    apply {
        pass = true;
        if(headers.icmp.isValid()) {
            pass  = false;
        }
    }
}

ebpfFilter(prs(), pipe()) main;