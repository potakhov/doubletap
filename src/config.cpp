// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#include "config.h"
#include "utils.h"

#include <boost/property_tree/json_parser.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>

namespace pt = boost::property_tree;

cfg cfg::instance;

void cfg::load(const std::string &path)
{
    pt::ptree pt;
    pt::read_json(path, pt);

    m_daemon = pt.get<bool>("app.daemon", false);
    m_logs = pt.get<std::string>("app.logs", std::string());

    m_device = pt.get<std::string>("main.device");
    m_nic_port_count = pt.get<uint32_t>("main.nicPorts", 1);
    m_queue_size_tune = pt.get<uint32_t>("main.nicQueueTune", 0);
    m_ring_size_tune = pt.get<uint32_t>("main.netmapRingSizeTune", 0);

    for (auto &item : pt.get_child("main.interfaces")) {
        std::string intf = item.second.data();
        if (!intf.empty()) {
            m_interfaces_to_watch.insert(inet_addr(intf.c_str()));
        }
    }

    uint32_t timeout = pt.get<uint32_t>("main.whitelistTimeout", 15);
    m_whitelist_timeout = timeout * 1000;

    m_mod_path = pt.get<std::string>("mod.path");
    m_netmap_ko = pt.get<std::string>("mod.netmap");
    m_driver_ko = pt.get<std::string>("mod.driver");

    m_driver_cpu = pt.get<int>("mod.driverCPU", 0);
    m_reflector_cpu = pt.get<int>("mod.reflectorCPU", 0);
    m_forwarder_cpu = pt.get<int>("mod.forwarderCPU", 0);

    auto strp = pt.get_child_optional("mod.startupCommand");
    if (strp) {
        for (auto &item : pt.get_child("mod.startupCommand")) {
            m_startup_commands.push_back(item.second.data());
        }
    }

    if (m_device.empty())
        throw std::runtime_error("Please specify the device to listen at.");

    if (m_interfaces_to_watch.empty())
        throw std::runtime_error("Please specify at least one interface to work with.");
}
