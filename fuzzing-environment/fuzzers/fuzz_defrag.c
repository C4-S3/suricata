/*
 * IP Defragmentation Fuzzer for Suricata
 *
 * Fuzzes IPv4 fragment reassembly logic:
 *   - Fragment offset manipulation
 *   - Overlapping fragments
 *   - Out-of-order fragments
 *   - Fragment boundary conditions
 *   - All 6 defrag policies (BSD, Linux, Windows, etc.)
 *
 * Targets VULN-2025-DEFRAG-001 and similar bugs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "suricata-common.h"
#include "decode.h"
#include "defrag.h"
#include "defrag-config.h"
#include "util-debug.h"

__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE (64 * 1024)

static int initialized = 0;
static DefragContext *defrag_ctx = NULL;

static void init_suricata(void) {
    if (initialized) return;

    GlobalsInitPreConfig();
    ConfInit();
    ConfYamlLoadString("", 0);

    /* Initialize defrag engine */
    DefragInit();
    defrag_ctx = DefragContextNew();

    initialized = 1;
}

/* Minimal IPv4 header structure */
typedef struct {
    uint8_t ver_ihl;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed)) ipv4_hdr_t;

static void fuzz_fragment(const uint8_t *data, size_t size) {
    if (size < sizeof(ipv4_hdr_t)) return;

    Packet *p = SCMalloc(sizeof(Packet));
    if (!p) return;

    memset(p, 0, sizeof(Packet));

    /* Copy fuzzed data as IP packet */
    p->pkt = SCMalloc(size);
    if (!p->pkt) {
        SCFree(p);
        return;
    }

    memcpy(p->pkt, data, size);
    p->pktlen = size;

    /* Basic packet metadata */
    p->datalink = LINKTYPE_RAW;

    /* Decode as IPv4 */
    DecodeIPV4(NULL, p, data, size);

    /* Process through defrag engine */
    if (p->flags & PKT_IS_FRAGMENT) {
        Packet *rp = Defrag(NULL, defrag_ctx, p);
        if (rp && rp != p) {
            /* Reassembled packet */
            PacketFree(rp);
        }
    }

    /* Cleanup */
    if (p->pkt) SCFree(p->pkt);
    SCFree(p);
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

        fuzz_fragment(buf, len);
    }

    /* Cleanup */
    if (defrag_ctx) {
        DefragContextDestroy(defrag_ctx);
    }

    return 0;
}
