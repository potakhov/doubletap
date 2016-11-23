// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <time.h>
#include <sys/types.h>
#include <string>
#include <deque>
#include <iostream>
#include <sstream>
#include <fstream>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>
#include <memory>
#include <chrono>
#include <ctime>
#include <vector>
#include <algorithm>
#include <set>
#include <condition_variable>
#include <signal.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <sys/poll.h>
#include <unordered_map>
#include <cstddef>

static const uint32_t version_major_k = 1;
static const uint32_t version_minor_k = 0;

static const uint64_t log_flush_timeout_k = 5000;
static const uint32_t maximum_log_line_size_k = 1024;
static const int log_handler_frequency_k = 50;
static const size_t max_packet_length_k = 2048;
static const size_t preallocated_buffer_size_k = 2048;
static const uint64_t syn_map_expire_check_timeout_k = 3000;
static const uint64_t syn_ack_reply_wait_time_k = 5000;

#define IP_HL(ip) (((ip)->ihl) & 0x0f)

#include "log.h"
