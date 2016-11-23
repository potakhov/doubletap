// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#define NETMAP_WITH_LIBS
#define ND(_fmt, ...) do {} while(0)
#define D(_fmt, ...) do {} while(0)
#define RD(_fmt, ...) do {} while(0)
#include <net/netmap_user.h>

#include "defines.h"
#include "nmtools.h"
#include "pqueue.h"
#include "config.h"
#include "utils.h"

// globals
sigset_t        g_signal_set;
siginfo_t       g_signal_info;
timespec        g_signal_timeout;

std::thread     g_threads[3];

nm_desc         *g_local_recv_descriptor = nullptr;
nm_desc         *g_local_descriptor = nullptr;
nm_desc         *g_nic_descriptor = nullptr;

int             g_raw_socket = -1;

std::unordered_map <uint64_t, uint64_t> g_whitelist;
std::unordered_map <uint64_t, std::unordered_map<uint32_t, uint64_t>> g_syn_records;
std::unordered_map <uint32_t, bool> g_interface_list;

uint64_t        g_syn_rotate = 0;

std::atomic_bool g_terminated;


int rx_slots_count(nm_desc *v_dsc)
{
    u_int i, tot = 0;

    for (i = v_dsc->first_rx_ring; i <= v_dsc->last_rx_ring; i++) {
        tot += nm_ring_space(NETMAP_RXRING(v_dsc->nifp, i));
    }

    return tot;
}

void move_rings(nm_desc *v_src, nm_desc *v_dst)
{
    u_int si = v_src->first_rx_ring, di = v_dst->first_tx_ring;

    while (si <= v_src->last_rx_ring && di <= v_dst->last_tx_ring) {
        netmap_ring *rxring = NETMAP_RXRING(v_src->nifp, si);
        netmap_ring *txring = NETMAP_TXRING(v_dst->nifp, di);

        if (nm_ring_empty(rxring)) {
            si++;
            continue;
        }

        if (nm_ring_empty(txring)) {
            di++;
            continue;
        }

        u_int rxpos = rxring->cur;
        u_int txpos = txring->cur;

        u_int rx_space = nm_ring_space(rxring);
        u_int tx_space = nm_ring_space(txring);

        if (rx_space > 0 && tx_space > 0) {
            while (1) {
                struct netmap_slot *rs = &rxring->slot[rxpos];
                struct netmap_slot *ts = &txring->slot[txpos];

                ts->len = rs->len;

                uint32_t pkt = ts->buf_idx;
                ts->buf_idx = rs->buf_idx;
                rs->buf_idx = pkt;

                ts->flags |= NS_BUF_CHANGED;
                rs->flags |= NS_BUF_CHANGED;

                txpos = nm_ring_next(txring, txpos);
                if (--tx_space == 0) break;

                rxpos = nm_ring_next(rxring, rxpos);
                if (--rx_space == 0) break;
            }
        }

        rxring->head = rxring->cur = rxpos;
        txring->head = txring->cur = txpos;
    }
}

void receive_packets(uint64_t v_clock, struct netmap_ring* v_ring)
{
    if (g_syn_rotate < v_clock) {
        for (auto wt = g_whitelist.begin(); wt != g_whitelist.end();) {
            if (wt->second < v_clock)
                g_whitelist.erase(wt++);
            else
                ++wt;
        }

        for (auto rt = g_syn_records.begin(); rt != g_syn_records.end();) {
            for (auto rec = rt->second.begin(); rec != rt->second.end();) {
                if (rec->second < v_clock)
                    rt->second.erase(rec++);
                else
                    ++rec;
            }
            if (rt->second.empty())
                g_syn_records.erase(rt++);
            else
                ++rt;
        }

        g_syn_rotate = v_clock + syn_map_expire_check_timeout_k;
    }

    u_int cur, rx, n;

    cur = v_ring->cur;
    n = nm_ring_space(v_ring);

    uint32_t pos = 0;

    for (rx = 0; rx < n; rx++) {
        struct netmap_slot* slot = &v_ring->slot[cur];
        char* p = NETMAP_BUF(v_ring, slot->buf_idx);

        struct iphdr *ip = (struct iphdr *) ((uint8_t *) p + ETH_HLEN);

        bool exclude = false;
        if (ip->protocol == IPPROTO_TCP) {
            if (g_interface_list.find(ip->daddr) != g_interface_list.end()) // we only trigger it for listed interfaces
            {
                tcphdr *hdr = (tcphdr *) ((uint8_t *) ip + 4 * IP_HL(ip));

                uint64_t iid = (static_cast<uint64_t>(ip->saddr) << 32) | static_cast<uint64_t>(ip->daddr);
                uint32_t pid = (static_cast<uint32_t>(hdr->source) << 16) | (static_cast<uint32_t>(hdr->dest));

                if (hdr->syn && !hdr->ack) {
                    auto white = g_whitelist.find(iid);
                    if (white == g_whitelist.end() || white->second < v_clock) {
                        // it's not whitelisted or expired so here we go

                        exclude = true;

                        // sending back SYN ACK
                        utils::gpacket packet;
                        utils::generate_packet(packet, hdr->dest, ip->daddr, hdr->source, ip->saddr, rand(), ntohl(hdr->seq) + 1, false);
                        struct sockaddr_in sin;
                        sin.sin_family = AF_INET;
                        sin.sin_port = hdr->source;
                        sin.sin_addr.s_addr = ip->saddr;
                        if (sendto(g_raw_socket, &packet, packet.headers.iph.iph_len, MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                            OLOGE << "Unable to send SYN ACK back to the client";
                        }

                        // renewing record
                        auto syn = g_syn_records.find(iid);
                        if (syn != g_syn_records.end()) {
                            syn->second[pid] = v_clock + syn_ack_reply_wait_time_k;
                        } else {
                            std::unordered_map<uint32_t, uint64_t> m;
                            m[pid] = v_clock + 5000;
                            g_syn_records.emplace(iid, m);
                        }
                    }
                } else {
                    if (!hdr->syn && hdr->ack) {
                        auto syn = g_syn_records.find(iid);
                        if (syn != g_syn_records.end()) {
                            auto rec = syn->second.find(pid);
                            if (rec != syn->second.end()) {
                                // this is our connection, we got ACK after SYN ACK
                                // let's now reset it

                                exclude = true;

                                // sending back RST
                                utils::gpacket packet;
                                utils::generate_packet(packet, hdr->dest, ip->daddr, hdr->source, ip->saddr, ntohl(hdr->ack_seq), ntohl(hdr->seq), true);
                                struct sockaddr_in sin;
                                sin.sin_family = AF_INET;
                                sin.sin_port = hdr->source;
                                sin.sin_addr.s_addr = ip->saddr;
                                if (sendto(g_raw_socket, &packet, packet.headers.iph.iph_len, MSG_NOSIGNAL, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
                                    OLOGE << "Unable to RST the connection";
                                }

                                // we don't renew the record here because ACK packets could be re-sent several times and we don't want them to prolong the whitelist
                                g_whitelist.insert(std::make_pair(iid, v_clock + cfg::instance.m_whitelist_timeout));
                                // not killing syn record here to make it reply RST again if the same ACK comes again within the set interval
                            }
                        }
                    }
                }
            }
        }

        if (!exclude && slot->len <= (max_packet_length_k - 2)) {
            *static_cast<uint16_t *>(static_cast<void *>(g_body_buffers[pos].body)) = slot->len;
            nm_pkt_copy(p, ((unsigned char *) g_body_buffers[pos].body) + 2, slot->len);
            if (++pos == preallocated_buffer_size_k) {
                enqueue_bulk(pos);
                pos = 0;
            }
        }

        cur = nm_ring_next(v_ring, cur);
    }

    if (pos > 0) {
        enqueue_bulk(pos);
    }

    v_ring->head = v_ring->cur = cur;
}

void netmap_receive_thread(nm_desc* v_netmap_descriptor)
{
    if (!v_netmap_descriptor) // top code failed to open it
        return;

    OLOGE << "Receiving thread has started";

    struct pollfd fds;
    fds.fd = v_netmap_descriptor->fd;
    fds.events = POLLIN;

    struct netmap_ring* rxring = NULL;
    struct netmap_if* nifp = v_netmap_descriptor->nifp;

    uint64_t clock;

    while (!g_terminated) {
        int poll_result = poll(&fds, 1, 1000);

        clock = utils::clock64();

        if (poll_result == 0) continue;

        if (poll_result == -1) {
            OLOGX << "Netmap poll failed with return code -1";
            break;
        }

        for (int i = v_netmap_descriptor->first_rx_ring; i <= v_netmap_descriptor->last_rx_ring; i++) {
            rxring = NETMAP_RXRING(nifp, i);
            if (nm_ring_empty(rxring)) continue;
            receive_packets(clock, rxring);
        }
    }

    nm_close(v_netmap_descriptor);

    OLOGE << "Receiving thread has stopped";
}

void netmap_reflector_thread(nm_desc* v_netmap_descriptor, nm_desc* v_local_descriptor)
{
    OLOGE << "Thread 'local_reflector' has started";

    // this one looks for packets destined out on a stack intf and sends them out from NIC

    pollfd fd_send[1];
    pollfd fd_receive[1];

    fd_receive[0].fd = v_local_descriptor->fd;
    fd_send[0].fd = v_netmap_descriptor->fd;

    while (!g_terminated) {
        // let's look if we have anything to send out
        int ninput = rx_slots_count(v_local_descriptor);

        int ret = 0;

        if (ninput) { // we already have some packets on local input ring
            fd_send[0].events = POLLOUT;
            fd_send[0].revents = 0;
            ret = poll(fd_send, 1, 1000);
        } else { // we don't have to send anything out, let's wait for packets in
            fd_receive[0].events = POLLIN;
            fd_receive[0].revents = 0;
            ret = poll(fd_receive, 1, 1000);
        }

        if (ret == 0) continue;

        if (ret == -1) {
            OLOGX << "Local stack poll returns -1";
            break;
        }

        if (ninput) {
            if (fd_send[0].revents & POLLOUT) {
                move_rings(v_local_descriptor, v_netmap_descriptor);

                if (!rx_slots_count(v_local_descriptor))
                {
                    // we transmitted everything
                    fd_send[0].events = POLLOUT;
                    fd_send[0].revents = 0;
                    poll(fd_send, 1, 0);
                }
            }
        }
    }

    OLOGE << "Thread 'local_reflector' has stopped";
}

void netmap_forwarder_thread(nm_desc* v_local_descriptor)
{
    OLOGE << "Thread 'local_forwarder' has started";

    // this one forwards incoming NIC packets from a queue to a local stack

    pollfd fds[1];
    fds[0].fd = v_local_descriptor->fd;

    while (!g_terminated) {
        size_t ninput = wait_dequeue_bulk(), nipos = 0;
        if (g_terminated)
            break;

        while (1) {
            fds[0].events = POLLOUT;
            fds[0].revents = 0;
            int ret = poll(fds, 1, 1000);

            if (ninput == nipos) break; // we don't have anything to send and flushed all out

            if (ret == 0) continue;

            if (ret == -1) {
                OLOGX << "Local out poll returns -1";
                break;
            }

            if (fds[0].revents & POLLOUT) {
                netmap_ring *txring;
                u_int di = v_local_descriptor->first_tx_ring;

                while (di <= v_local_descriptor->last_tx_ring) {
                    txring = NETMAP_TXRING(v_local_descriptor->nifp, di);
                    if (nm_ring_empty(txring)) {
                        di++;
                        continue;
                    }

                    u_int tx_space = nm_ring_space(txring);

                    if (tx_space > 0) {
                        u_int txpos = txring->cur;

                        while (1) {
                            struct netmap_slot *ts = &txring->slot[txpos];

                            ts->len = *static_cast<uint16_t *>(static_cast<void *>(g_receive_buffer[nipos].body));

                            char *txbuf = NETMAP_BUF(txring, ts->buf_idx);
                            nm_pkt_copy(g_receive_buffer[nipos].body + 2, txbuf, ts->len);

                            txpos = nm_ring_next(txring, txpos);
                            if (--tx_space == 0) break; // no more space in this ring

                            if (++nipos == ninput) break; // all done, exiting send loop
                        }

                        txring->head = txring->cur = txpos;

                        if (nipos == ninput) break; // we send everything, get out of ring loop
                    }
                }
            }
        }
    }

    OLOGE << "Thread 'local_forwarder' has stopped";
}

bool netmap::init()
{
    g_terminated = false;

    for (auto &ipaddr : cfg::instance.m_interfaces_to_watch)
        g_interface_list[ipaddr] = true;

    int tmp = 1;
    const int *val = &tmp;
    g_raw_socket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    if ( (g_raw_socket == -1) || (setsockopt(g_raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0) ) {
        OLOGE << "Unable to setup a raw socket!";
        return false;
    }

    std::string interface = "netmap:" + cfg::instance.m_device;

    nmreq base_nmd;
    bzero(&base_nmd, sizeof(base_nmd));
    base_nmd.nr_tx_rings = base_nmd.nr_rx_rings = 0;
    base_nmd.nr_tx_slots = base_nmd.nr_rx_slots = 0;

    g_nic_descriptor = nm_open(interface.c_str(), &base_nmd, 0, NULL);

    if (g_nic_descriptor == nullptr) {
        OLOGE << "Unable to open interface " << interface;
        return false;
    }

    OLOGE << "Mapped " << (g_nic_descriptor->req.nr_memsize >> 10) << "KB memory";
    OLOGE << "We have " << g_nic_descriptor->req.nr_tx_rings << " tx and " << g_nic_descriptor->req.nr_rx_rings << " rx rings";

    OLOGE << "Sleeping another 4 seconds to let the interface start";
    sleep(4);

    if (1 != g_nic_descriptor->req.nr_rx_rings)
    {
        OLOGE << "We are expected to have just one RX thread, configuration mismatch";
        nm_close(g_nic_descriptor);
        return false;
    }

    // creating read thread
    nm_desc nmd = *g_nic_descriptor;
    nmd.self = &nmd;
    uint64_t nmd_flags = 0;
    if (nmd.req.nr_flags != NR_REG_ALL_NIC) {
        OLOGX << "Main descriptor without NR_REG_ALL_NIC flag!";
    }

    nmd.req.nr_flags = NR_REG_ONE_NIC;
    nmd.req.nr_ringid = static_cast<uint16_t>(0);
    nmd_flags |= NETMAP_NO_TX_POLL;

    struct nm_desc *new_nmd = nm_open(interface.c_str(), NULL, nmd_flags | NM_OPEN_IFNAME | NM_OPEN_NO_MMAP, &nmd);

    if (new_nmd == nullptr) {
        OLOGX << "Unable to open netmap descriptor per hardware thread";
        nm_close(g_nic_descriptor);
        return false;
    } else {
        OLOGE << "Opening input thread for " << new_nmd->first_rx_ring << "-" << new_nmd->last_rx_ring << " hardware rings";
    }

    g_threads[0] = std::thread(netmap_receive_thread, new_nmd);
    utils::pthread_assign_cpu(g_threads[0].native_handle(), static_cast<uint32_t>(cfg::instance.m_driver_cpu), "rx");

    interface += "^";
    OLOGE << "Opening stack interface " << interface;

    g_local_descriptor = nm_open(interface.c_str(), NULL, NM_OPEN_NO_MMAP, g_nic_descriptor);
    if (g_local_descriptor == nullptr)
    {
        OLOGE << "Unable to open an interface " << interface;
        g_terminated = true;
        enqueue_null();
        g_threads[0].join();
        nm_close(g_nic_descriptor);
        return false;
    }

    g_local_recv_descriptor = nm_open(interface.c_str(), NULL, NETMAP_NO_TX_POLL | NM_OPEN_NO_MMAP, g_local_descriptor);
    if ((g_local_recv_descriptor == nullptr) || (g_local_recv_descriptor->mem != g_nic_descriptor->mem))
    {
        if ((g_local_recv_descriptor != nullptr) && (g_local_recv_descriptor->mem != g_nic_descriptor->mem))
        {
            OLOGE << "Unable to share memory with interface " << interface;
            nm_close(g_local_recv_descriptor);
        } else {
            OLOGE << "Unable to open additional receiver on an interface " << interface;
        }

        g_terminated = true;
        enqueue_null();
        g_threads[0].join();

        nm_close(g_local_descriptor);
        nm_close(g_nic_descriptor);
        return false;
    }

    OLOGE << "Opening reflector thread for " << g_nic_descriptor->first_tx_ring << "-" << g_nic_descriptor->last_tx_ring << " hardware rings";
    g_threads[1] = std::thread(netmap_reflector_thread, g_nic_descriptor, g_local_recv_descriptor);

    if (cfg::instance.m_reflector_cpu) {
        utils::pthread_assign_cpu(g_threads[1].native_handle(), static_cast<uint32_t>(cfg::instance.m_reflector_cpu), "reflector");
    }

    OLOGE << "Opening forwarder thread for " << g_local_descriptor->first_tx_ring << "-" << g_local_descriptor->last_tx_ring << " rings";
    g_threads[2] = std::thread(netmap_forwarder_thread, g_local_descriptor);

    if (cfg::instance.m_forwarder_cpu) {
        utils::pthread_assign_cpu(g_threads[2].native_handle(), static_cast<uint32_t>(cfg::instance.m_forwarder_cpu), "forwarder");
    }

    sigemptyset(&g_signal_set);
    sigaddset(&g_signal_set, SIGQUIT);
    sigaddset(&g_signal_set, SIGPIPE);
    sigaddset(&g_signal_set, SIGABRT);
    sigaddset(&g_signal_set, SIGTERM);
    sigaddset(&g_signal_set, SIGINT);
    sigaddset(&g_signal_set, SIGSEGV);
    sigaddset(&g_signal_set, SIGFPE);
    sigaddset(&g_signal_set, SIGILL);
    sigaddset(&g_signal_set, SIGHUP);
    sigaddset(&g_signal_set, SIGUSR1);
    sigaddset(&g_signal_set, SIGUSR2);

    pthread_sigmask(SIG_BLOCK, &g_signal_set, NULL);

    g_signal_timeout.tv_sec = 1;
    g_signal_timeout.tv_nsec = 0;

    memset(static_cast<void*>(&g_signal_info), 0, sizeof(siginfo_t));

    return true;
}

void on_signal(const int v_signum)
{
    if (v_signum != SIGHUP && v_signum != SIGUSR1 && v_signum != SIGUSR2) {
        g_terminated = true;
        enqueue_null();
    }
}

void netmap::loop()
{
    while (!g_terminated)
    {
        int res = sigtimedwait(&g_signal_set, &g_signal_info, &g_signal_timeout);
        if (res != -1)
            on_signal(g_signal_info.si_signo);
    }
}

void netmap::terminate()
{
    for (int i = 0; i < 3; i++) g_threads[i].join();

    nm_close(g_local_recv_descriptor);
    nm_close(g_local_descriptor);
    nm_close(g_nic_descriptor);
}
