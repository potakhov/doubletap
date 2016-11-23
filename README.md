# doubletap
### TCP SYN Authorization emulation daemon for ixgbe/igb.
===============

Simplified mitigation solution that implements widely used TCP SYN Authorization mechanism to prevent SYN flood from hitting the server.  
For simplicity this app limits the number of NIC RSS RX/TX queues to one so it shouldn't be used in any production development.  The goal of this project was to create a test stand allowing client side developers to debug and test their apps behavior in the edge cases when the server side is affected by SYN Authorization mechanism.  
The app is using Netmap library, kernel module and modified drivers to take over the NIC however it copies all the packets it gets (except for the initial SYN and ACK from a first sequence) back to the kernel networking stack so it may be used with any server software you need to test with.  
**As for now solution is IPv4-only.**

## TCP SYN Authorization

Citing [Defcon presentation](https://www.defcon.org/images/defcon-21/dc-21-presentations/Mui-Lee/DEFCON-21-Miu-Lee-Kill-em-All-DDoS-Protection-Total-Annihilation-WP-Updated.pdf)

__With this method, the authenticity of the client’s TCP stack is validated through testing for correct response to exceptional conditions, such that spoofed source IPs and most raw-socket-based DDoS clients can be detected. Common tactics include sending back a RST packet on the first SYN expecting the client to retry, as well as deliberately sending back a SYN-ACK with wrong sequence number expecting the client to send back as RST and then retry.__

This application implements the first method - sending back an RST packet after the successfull SYN-SYN/ACK-ACK handshake and then whitelisting the source address for a timeout specified in configuration file.

## Dependencies

### Building
- Netmap library (https://github.com/luigirizzo/netmap)
- Boost (http://www.boost.org). It is used only to parse the configuration file in src/config.cpp and could be easily stripped out.
- CMake

### OS (verified)
- CentOS 6.x, CentOS 7.x

### Hardware
- Intel igb
- Intel ixgbe

## Compiling

```shell
git clone https://github.com/potakhov/doubletap.git
cd doubletap
mkdir build ; cd build
cmake .. -DNETMAP_DIR=/path/to/netmap/sys/
make
```

## Configuration file parameters and usage

To launch the app simply use

```shell
./doubletap /etc/doubletap.d/doubletap.conf
```

Sample configuration file is below

```javascript
{
  "app" : {
    "daemon" : true,
    "logs" : "/var/log/doubletap.d"
  },
  "main" : {
    "device" : "eth0",
    "nicPorts" : 2,
    "nicQueueTune" : 4096,
    "netmapRingSizeTune" : 70000,
    "interfaces" : ["192.168.1.10", "192.168.10.11"],
    "whitelistTimeout" : 15
  },
  "mod" : {
    "path" : "/usr/local/doubletap.d",
    "netmap" : "netmap.ko",
    "driver" : "igb.ko",
    "driverCPU" : 1,
    "reflectorCPU" : 2,
    "forwarderCPU" : 3,
    "startupCommand" : ["ifup eth0", "ifup eth1"]
  }
}
```

## 3rd party software

Uses [ConcurrentQueue](https://github.com/cameron314/concurrentqueue) (included in sources)
