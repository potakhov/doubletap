// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include "defines.h"

struct cfg {
    cfg() : m_reflector_cpu(0),
            m_forwarder_cpu(0), m_daemon(false), m_driver_cpu(0),
            m_nic_port_count(0), m_queue_size_tune(0), m_ring_size_tune(0) { }

    void load(const std::string& path);
    static cfg instance;

    // device name
    std::string m_device;

    // path to the mod .ko files
    std::string m_mod_path;
    // netmap and driver .ko file names
    std::string m_netmap_ko, m_driver_ko;

    int m_driver_cpu;
    // CPUs for reflector and forwarder threads
    int m_reflector_cpu, m_forwarder_cpu;

    // set of interface startup commands (if needed)
    std::vector <std::string> m_startup_commands;

    // list of interfaces to apply the filter on
    std::set <uint32_t> m_interfaces_to_watch;

    // set this to try to tune hardware queue size
    int m_queue_size_tune;

    // set this to try to tune netmap ring size
    int m_ring_size_tune;

    // work mode
    bool m_daemon;
    // log folder path
    std::string m_logs;

    // number of NIC ports (used to set correct RSS parameter)
    uint32_t m_nic_port_count;

    // timeout in msec for an IP to stay whitelisted
    uint64_t m_whitelist_timeout;
};
