/*
 * DNS Protocol Fuzzer for Suricata
 *
 * Fuzzes DNS query/response parsing:
 *   - Query/response headers
 *   - Question section
 *   - Answer/Authority/Additional records
 *   - Name compression
 *   - DNSSEC records
 *   - Various record types (A, AAAA, MX, TXT, etc.)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suricata-common.h"
#include "app-layer-dns-common.h"
#include "app-layer-dns-udp.h"
#include "app-layer-parser.h"
#include "flow.h"

__AFL_FUZZ_INIT();

#define MAX_INPUT_SIZE (64 * 1024)

static int initialized = 0;

static void init_suricata(void) {
    if (initialized) return;

    GlobalsInitPreConfig();
    ConfInit();
    ConfYamlLoadString("", 0);
    AppLayerSetup();
    AppLayerParserRegisterProtocolParsers();

    initialized = 1;
}

static void fuzz_dns_packet(const uint8_t *data, size_t size, uint8_t direction) {
    Flow f;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));

    f.proto = IPPROTO_UDP;
    f.alproto = ALPROTO_DNS;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* Parse DNS packet */
    AppLayerParserParse(NULL, alp_ctx, &f, ALPROTO_DNS,
        direction, (uint8_t *)data, size);

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        DNSState *dns_state = f.alstate;
        DNSStateFree(dns_state);
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

        if (len < 12 || len > MAX_INPUT_SIZE)  /* DNS header is 12 bytes */
            continue;

        /* DNS header flags at offset 2-3
         * QR bit (byte 2, bit 7): 0=query, 1=response
         */
        uint8_t direction = (buf[2] & 0x80) ?
            STREAM_TOCLIENT : STREAM_TOSERVER;

        fuzz_dns_packet(buf, len, direction);
    }

    return 0;
}
