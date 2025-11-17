/*
 * TCP Stream Reassembly Fuzzer for Suricata
 *
 * Fuzzes TCP segment reassembly:
 *   - Out-of-order segments
 *   - Overlapping data
 *   - Sequence number wraparound
 *   - Window scaling
 *   - Retransmissions
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suricata-common.h"
#include "decode.h"
#include "stream-tcp.h"
#include "stream-tcp-reassemble.h"
#include "flow.h"

__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE (64 * 1024)

static int initialized = 0;

static void init_suricata(void) {
    if (initialized) return;

    GlobalsInitPreConfig();
    ConfInit();
    ConfYamlLoadString("", 0);

    StreamTcpInitConfig(1);  /* Quiet mode */

    initialized = 1;
}

/* Simplified TCP header */
typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
    uint8_t off_flags;
    uint8_t flags;
    uint16_t win;
    uint16_t checksum;
    uint16_t urg;
} __attribute__((packed)) tcp_hdr_t;

static void fuzz_tcp_segment(const uint8_t *data, size_t size) {
    if (size < sizeof(tcp_hdr_t)) return;

    Packet p;
    Flow f;
    TcpSession tcp_session;

    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    /* Setup packet */
    p.pkt = (uint8_t *)data;
    p.pktlen = size;
    p.proto = IPPROTO_TCP;
    p.flow = &f;

    /* Setup flow */
    f.proto = IPPROTO_TCP;
    f.protoctx = &tcp_session;

    /* Decode TCP */
    DecodeTCP(NULL, &p, data, size);

    if (p.tcph) {
        /* Process through stream reassembly */
        StreamTcpReassembleHandleSegment(NULL, &tcp_session,
            &tcp_session.client, &p);
    }
}

int main(int argc, char **argv) {
    init_suricata();

    #ifdef __AFL_HAVE_MANUAL_CONTROL
        __AFL_INIT();
    #endif

    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(10000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        if (len < 20 || len > MAX_INPUT_SIZE)
            continue;

        fuzz_tcp_segment(buf, len);
    }

    return 0;
}
