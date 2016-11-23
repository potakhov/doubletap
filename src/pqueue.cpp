// doubletap TCP SYN Authorization test stand
// ©2016 Alexey Potakhov [https://github.com/potakhov/doubletap]

#include "pqueue.h"
#include "../3rdparty/blockingconcurrentqueue.h"

// packets

packet_body g_body_buffers[preallocated_buffer_size_k];
packet_body g_receive_buffer[preallocated_buffer_size_k];

moodycamel::BlockingConcurrentQueue <packet_body> g_packets;

void enqueue_null()
{
    packet_body pb;
    memset(pb.body, 0, max_packet_length_k);
    g_packets.enqueue(pb);
}

void enqueue_bulk(unsigned int v_size)
{
    g_packets.enqueue_bulk(g_body_buffers, v_size);
}

size_t wait_dequeue_bulk()
{
    return g_packets.wait_dequeue_bulk(g_receive_buffer, preallocated_buffer_size_k);
}
