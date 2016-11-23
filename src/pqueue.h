// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#pragma once

#include "defines.h"
#include "nmtools.h"

// packets

struct packet_body {
    unsigned char body[max_packet_length_k];
};

extern packet_body g_body_buffers[preallocated_buffer_size_k];
extern packet_body g_receive_buffer[preallocated_buffer_size_k];

extern void enqueue_null();
extern void enqueue_bulk(unsigned int v_size);
extern size_t wait_dequeue_bulk();
