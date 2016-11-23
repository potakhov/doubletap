// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#include "utils.h"
#include "config.h"

timespec start_tics_clock64;
const int NANOSECONDS_PER_SECOND = 1000000000;

uint64_t utils::clock64()
{
    timespec tics_clock64;
    clock_gettime(CLOCK_REALTIME, &tics_clock64);

    if(tics_clock64.tv_nsec > NANOSECONDS_PER_SECOND)
    {
        tics_clock64.tv_sec += tics_clock64.tv_nsec / NANOSECONDS_PER_SECOND;
        tics_clock64.tv_nsec %= NANOSECONDS_PER_SECOND;
    }

    uint64_t msecresult = (static_cast<uint64_t>(tics_clock64.tv_sec) - static_cast<uint64_t>(start_tics_clock64.tv_sec)) * 1000LL;
    if (static_cast<uint64_t>(tics_clock64.tv_nsec) > static_cast<uint64_t>(start_tics_clock64.tv_nsec))
        msecresult += (static_cast<uint64_t>(tics_clock64.tv_nsec) - static_cast<uint64_t>(start_tics_clock64.tv_nsec)) / 1000000LL;
    else
        msecresult -= (static_cast<uint64_t>(start_tics_clock64.tv_nsec) - static_cast<uint64_t>(tics_clock64.tv_nsec)) / 1000000LL;

    return msecresult;
}

void utils::init_clock64()
{
    clock_gettime(CLOCK_REALTIME, &start_tics_clock64);
    if(start_tics_clock64.tv_nsec > NANOSECONDS_PER_SECOND)
    {
        start_tics_clock64.tv_sec += start_tics_clock64.tv_nsec / NANOSECONDS_PER_SECOND;
        start_tics_clock64.tv_nsec %= NANOSECONDS_PER_SECOND;
    }
}

bool utils::manage_interface_promisc_mode(bool v_switch_on)
{
    int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (!fd) {
        OLOGE << "Unable to create a socket to change promisc mode";
        return false;
    }

    struct ifreq ethreq;
    memset(&ethreq, 0, sizeof(ethreq));
    strncpy(ethreq.ifr_name, cfg::instance.m_device.c_str(), IFNAMSIZ);

    int ioctl_res = ioctl(fd, SIOCGIFFLAGS, &ethreq);

    if (ioctl_res == -1) {
        OLOGE << "Unable to get interface flags";
        return false;
    }

    bool promisc_enabled_on_device = (ethreq.ifr_flags & IFF_PROMISC) != 0;

    if (v_switch_on) {
        if (promisc_enabled_on_device) {
            OLOGE << "Interface " << cfg::instance.m_device << " is in promisc mode already";
            return true;
        } else {
            OLOGE << "Interface is not in promisc mode currently, switching it on";
            ethreq.ifr_flags |= IFF_PROMISC;

            int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);

            if (ioctl_res_set == -1) {
                OLOGE << "Unable to set interface flags";
                return false;
            }

            return true;
        }
    } else {
        if (!promisc_enabled_on_device) {
            OLOGE << "Interface " << cfg::instance.m_device << " is in normal mode already";
            return true;
        } else {
            OLOGE << "Interface is in promisc mode now, switching it off";

            ethreq.ifr_flags &= ~IFF_PROMISC;
            int ioctl_res_set = ioctl(fd, SIOCSIFFLAGS, &ethreq);

            if (ioctl_res_set == -1) {
                OLOGE << "Unable to set interface flags";
                return false;
            }

            return true;
        }
    }
}

void utils::tune_interface_settings()
{
    std::stringstream str;

    OLOGE << "Turning off NIC offloading for " << cfg::instance.m_device;

    str << "ethtool -K " << cfg::instance.m_device << " tx off tso off gso off sg off gro off lro off";
    system(str.str().c_str()); str.str(std::string());

    OLOGE << "Enabling UDP RSS flow hash for " << cfg::instance.m_device;

    str << "ethtool -N " << cfg::instance.m_device << " rx-flow-hash udp4 sdfn";
    system(str.str().c_str()); str.str(std::string());

    OLOGE << "Ajusting txqueuelen for " << cfg::instance.m_device;

    str << "ifconfig " << cfg::instance.m_device << " txqueuelen 16000";
    system(str.str().c_str()); str.str(std::string());

    OLOGE << "Turning off auto-negotiation for " << cfg::instance.m_device;

    str << "ethtool -A " << cfg::instance.m_device << " autoneg off rx off tx off";
    system(str.str().c_str()); str.str(std::string());

    if (cfg::instance.m_queue_size_tune) {
        OLOGE << "Tuning NIC queue sizes";
        str << "ethtool -G " << cfg::instance.m_device << " rx " << cfg::instance.m_queue_size_tune << " tx " << cfg::instance.m_queue_size_tune;
        system(str.str().c_str());
    }

    if (cfg::instance.m_ring_size_tune) {
        OLOGE << "Tuning netmap ring size";
        FILE *fp = fopen("/sys/module/netmap/parameters/ring_size", "wb");
        if (fp) {
            fprintf(fp, "%d", cfg::instance.m_ring_size_tune);
            fclose(fp);
        }
    }
}

bool utils::assign_irq_handlers()
{
    FILE *fp;
    char buf[100];
    std::vector <int> irqs;

    int numq = 0;
    std::stringstream cmd;
    cmd << "grep \"" << cfg::instance.m_device << "-TxRx\" /proc/interrupts | awk '{print $1}' | sed 's/://'";
    fp = popen(cmd.str().c_str(), "r");
    if (fp)
    {
        while (1) {
            if (fgets(buf, 100, fp)) {
                int irq = atoi(buf);
                if (irq != 0)
                    irqs.push_back(irq);
            } else {
                break;
            }
        }
        fclose(fp);
    }

    if (irqs.size() != 1)
    {
        OLOGE << "Number of NIC IRQs is not 1, skipping setup";
        return false;
    } else {
        for (int i = 0; i < irqs.size(); i++)
        {
            std::stringstream line;
            line << "/proc/irq/" << irqs[i] << "/smp_affinity";
            int cpu = 1 << (cfg::instance.m_driver_cpu);
            OLOGE << "Writing " << std::hex << cpu << " to " << std::dec << line.str();
            fp = fopen(line.str().c_str(), "wb");
            if (fp)
            {
                fprintf(fp, "%x", cpu);
                fclose(fp);
            }
        }
        return true;
    }
}

void utils::replace_mod_files()
{
    std::stringstream cmd;
    cmd << "rmmod " << cfg::instance.m_driver_ko;
    OLOGE << "Removing " << cfg::instance.m_driver_ko << " module";
    system(cmd.str().c_str()); cmd.str(std::string());

    cmd << "rmmod " << cfg::instance.m_netmap_ko;
    OLOGE << "Removing " << cfg::instance.m_netmap_ko << " module";
    system(cmd.str().c_str()); cmd.str(std::string());

    cmd << "insmod " << cfg::instance.m_mod_path << "/" << cfg::instance.m_netmap_ko;
    OLOGE << "Adding: " << cmd.str();
    system(cmd.str().c_str()); cmd.str(std::string());

    cmd << "insmod " << cfg::instance.m_mod_path << "/" << cfg::instance.m_driver_ko;

    // we are strictly limiting number of RX queues to 1 for simplicity
    if (cfg::instance.m_nic_port_count <= 1)
    {
        cmd << " RSS=1";
    } else {
        std::string RSS, NUM = std::string("1");
        for (size_t nm = 0; nm < cfg::instance.m_nic_port_count; nm++) {
            if (!RSS.empty()) RSS.append(",");
            RSS.append(NUM);
        }
        cmd << " RSS=" << RSS;
    }

    OLOGE << "Adding: " << cmd.str();
    system(cmd.str().c_str());

    OLOGE << "Sleeping 4 seconds to let device initialize";
    sleep(4);

    if (!cfg::instance.m_startup_commands.empty()) {
        for (auto &cmd : cfg::instance.m_startup_commands) {
            OLOGE << "Invoking: " << cmd;
            system(cmd.c_str());
        }
    }
}

void utils::pthread_assign_cpu(pthread_t v_thread, uint32_t v_cpu, const char *v_name)
{
    cpu_set_t current_cpu_set;
    CPU_ZERO(&current_cpu_set);
    CPU_SET(v_cpu, &current_cpu_set);
    OLOGE << "Binding " << v_name << " thread to logical CPU: " << v_cpu;
    int set_affinity_result = pthread_setaffinity_np(v_thread, sizeof(cpu_set_t), &current_cpu_set);
    if (set_affinity_result != 0) {
        OLOGX << "Unable to set CPU affinity for " << v_name << " thread";
    }
}

unsigned short utils::csum(unsigned short *v_buf, int v_nwords)
{
    unsigned long sum;
    for (sum = 0; v_nwords > 0; v_nwords--) sum += *v_buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

uint16_t utils::tcp_csum(const utils::gpacket& v_packet)
{
    uint32_t sum = 0x0;
    union pseudo_header {
        struct {
            uint32_t m_src_ip;
            uint32_t m_dst_ip;
            uint8_t m_reserved;
            uint8_t m_protocol;
            uint16_t m_segment_size;
            utils::tcpheader m_tcp_header;
        } data;
        uint16_t m_pad[sizeof(data)/sizeof(uint16_t)];
        uint8_t m_raw[sizeof(data)];
    };

    pseudo_header h;
    h.data.m_dst_ip = v_packet.headers.iph.iph_destip;
    h.data.m_src_ip = v_packet.headers.iph.iph_sourceip;
    h.data.m_reserved = 0;
    h.data.m_protocol = v_packet.headers.iph.iph_protocol;
    h.data.m_segment_size = htons(sizeof(v_packet.headers.tcph));
    memcpy(&h.data.m_tcp_header, &v_packet.headers.tcph, sizeof(utils::tcpheader));

    for( auto &x: h.m_pad) {
        sum += ntohs(x);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
}

void utils::generate_packet(utils::gpacket &v_packet, uint16_t v_sport, uint32_t v_saddr, uint16_t v_dport, uint32_t v_daddr, uint32_t v_sequence, uint32_t v_ack, bool v_reset)
{
    struct utils::ipheader *iph = &v_packet.headers.iph;
    struct utils::tcpheader *tcph = &v_packet.headers.tcph;

    memset(&v_packet, 0, sizeof(v_packet));
    iph->iph_ihl = 5;
    iph->iph_ver = 4;
    iph->iph_tos = 0;
    iph->iph_len = sizeof(struct utils::ipheader) + sizeof(struct utils::tcpheader);
    iph->iph_ident = 0xffff;
    iph->iph_offset = 2 << 5;
    iph->iph_ttl = 64;
    iph->iph_protocol = 6;
    iph->iph_chksum = 0;
    iph->iph_sourceip = v_saddr;
    iph->iph_destip = v_daddr;
    tcph->tcph_srcport = v_sport;
    tcph->tcph_destport = v_dport;
    tcph->tcph_seqnum = htonl(v_sequence);
    tcph->tcph_acknum = htonl(v_ack);
    tcph->tcph_offset = 0x5;
    if (v_reset) {
        tcph->tcph_rst = 0x01;
        tcph->tcph_ack = 0x01;
    } else {
        tcph->tcph_syn = 0x01;
        tcph->tcph_ack = 0x01;
    }
    tcph->tcph_win = 16384;
    tcph->tcph_chksum = 0;
    tcph->tcph_urgptr = 0;
    tcph->tcph_chksum = htons(utils::tcp_csum(v_packet));
    iph->iph_chksum = utils::csum((unsigned short *) &v_packet, iph->iph_len >> 1);
}
