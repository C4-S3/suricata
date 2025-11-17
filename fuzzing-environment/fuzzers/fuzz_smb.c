/*
 * SMB Protocol Fuzzer for Suricata
 *
 * Fuzzes SMB/SMB2/SMB3 parsing:
 *   - SMB headers
 *   - Command structures
 *   - File operations
 *   - Transaction requests
 *   - Dialect negotiation
 *   - Security blobs
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "suricata-common.h"
#include "app-layer-smb.h"
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

static void fuzz_smb_packet(const uint8_t *data, size_t size, uint8_t direction) {
    Flow f;
    TcpSession tcp_session;
    AppLayerParserThreadCtx *alp_ctx;

    memset(&f, 0, sizeof(f));
    memset(&tcp_session, 0, sizeof(tcp_session));

    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;
    f.protoctx = &tcp_session;

    alp_ctx = AppLayerParserThreadCtxAlloc();
    if (!alp_ctx) return;

    /* Parse SMB data */
    AppLayerParserParse(NULL, alp_ctx, &f, ALPROTO_SMB,
        direction, (uint8_t *)data, size);

    /* Cleanup */
    AppLayerParserThreadCtxFree(alp_ctx);

    if (f.alstate) {
        SMBState *smb_state = f.alstate;
        SMBStateFree(smb_state);
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

        /* SMB header:
         *   SMB1: \xFFSMB (4 bytes)
         *   SMB2/3: \xFESMB (4 bytes)
         * NetBIOS session service adds 4-byte length header
         */

        if (len < 8 || len > MAX_INPUT_SIZE)
            continue;

        /* Determine direction from SMB flags */
        uint8_t direction = STREAM_TOSERVER;

        if (len > 4) {
            /* Check for response bit in SMB header */
            if (memcmp(buf, "\xFF\x53\x4D\x42", 4) == 0) {  /* SMB1 */
                if (len > 9 && (buf[9] & 0x80)) {
                    direction = STREAM_TOCLIENT;
                }
            } else if (memcmp(buf, "\xFE\x53\x4D\x42", 4) == 0) {  /* SMB2/3 */
                if (len > 16 && (buf[16] & 0x01)) {
                    direction = STREAM_TOCLIENT;
                }
            }
        }

        fuzz_smb_packet(buf, len, direction);
    }

    return 0;
}
