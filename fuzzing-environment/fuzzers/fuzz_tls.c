/*
 * TLS/SSL Protocol Fuzzer for Suricata
 *
 * Fuzzes TLS handshake and record parsing:
 *   - ClientHello/ServerHello
 *   - Certificate messages
 *   - Key exchange
 *   - Cipher suites
 *   - Extensions
 *   - Record fragmentation
 *
 * Targets common TLS vulnerabilities:
 *   - Heartbleed-like overreads
 *   - Certificate parsing bugs
 *   - Extension handling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suricata-common.h"
#include "app-layer-ssl.h"
#include "app-layer-parser.h"
#include "flow.h"
#include "stream-tcp.h"

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

static void fuzz_tls_packet(const uint8_t *data, size_t size, uint8_t direction) {
    Flow f;
    TcpSession tcp_session;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_TLS;
    f.protoctx = &tcp_session;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* Parse TLS data */
    AppLayerParserParse(
        NULL, alp_ctx, &f, ALPROTO_TLS,
        direction, (uint8_t *)data, size
    );

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        SSLState *ssl_state = f.alstate;
        SSLStateFree(ssl_state);
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

        if (len < 5 || len > MAX_INPUT_SIZE)
            continue;

        /* TLS record format:
         *   byte 0: content type (0x16 = handshake, 0x17 = application data)
         *   byte 1-2: version
         *   byte 3-4: length
         */

        /* Alternate between client and server messages */
        uint8_t direction = (buf[0] & 0x01) ? STREAM_TOSERVER : STREAM_TOCLIENT;

        fuzz_tls_packet(buf, len, direction);
    }

    return 0;
}
