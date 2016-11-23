// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include "defines.h"

namespace utils {

#pragma pack(1)

    struct ipheader {
        uint8_t iph_ihl : 4;
        uint8_t iph_ver : 4;
        uint8_t iph_tos;
        uint16_t iph_len;
        uint16_t iph_ident;
        uint16_t iph_offset;
        uint8_t iph_ttl;
        uint8_t iph_protocol;
        uint16_t iph_chksum;
        uint32_t iph_sourceip;
        uint32_t iph_destip;
    };

    struct tcpheader {
        uint16_t tcph_srcport;
        uint16_t tcph_destport;
        uint32_t tcph_seqnum;
        uint32_t tcph_acknum;
        uint8_t tcph_reserved : 4;
        uint8_t tcph_offset : 4;

        uint8_t tcph_fin : 1;
        uint8_t tcph_syn : 1;
        uint8_t tcph_rst : 1;
        uint8_t tcph_psh : 1;
        uint8_t tcph_ack : 1;
        uint8_t tcph_urg : 1;
        uint8_t tcph_ece : 1;
        uint8_t tcph_cwr : 1;

        uint16_t tcph_win;
        uint16_t tcph_chksum;
        uint16_t tcph_urgptr;
    };

    union gpacket {
        struct {
            struct utils::ipheader iph;
            struct utils::tcpheader tcph;
        } headers;
        char datagram[sizeof(headers)];
    };

#pragma pack()

    void init_clock64();
    uint64_t clock64();
    bool manage_interface_promisc_mode(bool v_switch_on);
    void tune_interface_settings();
    bool assign_irq_handlers();
    void replace_mod_files();
    void pthread_assign_cpu(pthread_t v_thread, uint32_t v_cpu, const char *v_name);

    unsigned short csum(unsigned short *v_buf, int v_nwords);
    uint16_t tcp_csum(const utils::gpacket& v_packet);
    void generate_packet(utils::gpacket &v_packet, uint16_t v_sport, uint32_t v_saddr, uint16_t v_dport, uint32_t v_daddr, uint32_t v_sequence, uint32_t v_ack, bool v_reset);
}
