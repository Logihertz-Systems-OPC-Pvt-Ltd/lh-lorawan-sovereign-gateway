#include "lorawan_types.h"
#include "aes128_cmac.h"
#include "lorawan_mac.h"
#include "json_parser.h"
#include "lorawan_auditor.h"
#include "exporters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LH_LORAWAN_VERSION "0.1.0"

static void print_version(void) {
    printf("lh-lorawan-sovereign-gateway v%s\n", LH_LORAWAN_VERSION);
    printf("Logihertz Systems (OPC) Private Limited - Sovereign LoRaWAN Air-Gapped Gateway Engine\n");
}

static void print_help(const char *prog_name) {
    printf("Usage: %s <command> [options]\n\n", prog_name);
    printf("Production-grade, zero-dependency C11 air-gapped LoRaWAN Gateway, OTAA Join Server,\n");
    printf("AES-128-CMAC MIC Verifier, Time-on-Air Engine, and 10-Rule Security Auditor.\n\n");
    printf("Commands:\n");
    printf("  audit <policy.json>       Audit gateway security policy against 10 sovereign rules\n");
    printf("  join-otaa <raw_hex>       Verify OTAA Join-Request MIC & derive session keys\n");
    printf("  verify-uplink <raw_hex>   Verify uplink MIC, check 32-bit FCnt, decrypt payload\n");
    printf("  calc-toa                  Calculate LoRa CSS Time-on-Air and duty-cycle constraints\n");
    printf("  --version, -v             Display version and exit\n");
    printf("  --help, -h                Display this help documentation and exit\n\n");
    printf("Options for 'audit':\n");
    printf("  --format=table|json|sarif Output format (default: table)\n");
    printf("  --output=<file>           Write audit report to file instead of stdout\n\n");
    printf("Options for 'join-otaa':\n");
    printf("  --app-key=<32-hex>        Device 128-bit AppKey (required)\n");
    printf("  --join-nonce=<6-hex>      JoinNonce / AppNonce (default: 010203)\n");
    printf("  --net-id=<6-hex>          NetID (default: 000001)\n");
    printf("  --dev-addr=<8-hex>        Assigned DevAddr (default: 00112233)\n\n");
    printf("Options for 'verify-uplink':\n");
    printf("  --nwk-skey=<32-hex>       Network Session Key for MIC verification (required)\n");
    printf("  --app-skey=<32-hex>       Application Session Key for payload decryption (required)\n");
    printf("  --dev-addr=<8-hex>        Device Address (required)\n");
    printf("  --fcnt=<uint32>           Expected / prior 32-bit FCnt counter (default: 0)\n");
    printf("  --freq=<mhz>              Uplink center frequency in MHz (default: 865.0625)\n");
    printf("  --region=IN865|EU868      Regional band plan (default: IN865)\n\n");
    printf("Options for 'calc-toa':\n");
    printf("  --sf=<7-12>               Spreading Factor (default: 7)\n");
    printf("  --bw=<125|250|500>        Bandwidth in kHz (default: 125)\n");
    printf("  --cr=<1-4>                Coding rate 4/(CR+4): 1=4/5, 2=4/6, etc. (default: 1)\n");
    printf("  --payload=<bytes>         Payload size in bytes (default: 16)\n");
    printf("  --preamble=<symbols>      Preamble symbols (default: 8)\n");
    printf("  --region=IN865|EU868      Regional regulatory plan (default: IN865)\n");
    printf("  --format=table|json       Output format (default: table)\n\n");
    printf("Examples:\n");
    printf("  %s audit fixtures/hardened_lorawan_policy.json\n", prog_name);
    printf("  %s audit fixtures/vulnerable_lorawan_policy.json --format=json\n", prog_name);
    printf("  %s calc-toa --sf=12 --bw=125 --payload=23 --region=IN865\n", prog_name);
}

static int cmd_audit(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: audit command requires a policy JSON file path.\n");
        return 1;
    }

    const char *policy_file = argv[2];
    const char *format = "table";
    const char *output_file = NULL;

    for (int i = 3; i < argc; i++) {
        if (strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        } else if (strncmp(argv[i], "--output=", 9) == 0) {
            output_file = argv[i] + 9;
        }
    }

    gateway_policy_t policy;
    if (!json_load_policy_file(policy_file, &policy)) {
        fprintf(stderr, "Error: failed to load or parse policy file '%s'.\n", policy_file);
        return 1;
    }

    audit_report_t report;
    lorawan_audit_policy(&policy, &report);

    FILE *out = stdout;
    if (output_file) {
        out = fopen(output_file, "w");
        if (!out) {
            fprintf(stderr, "Error: failed to open output file '%s' for writing.\n", output_file);
            return 1;
        }
    }

    if (strcmp(format, "json") == 0) {
        export_audit_json(&report, out);
    } else if (strcmp(format, "sarif") == 0) {
        export_audit_sarif(&report, out);
    } else {
        export_audit_table(&report, out);
    }

    if (output_file) {
        fclose(out);
    }

    /* Return 0 if posture score >= 80, otherwise return 1 */
    return (report.posture_score >= 80) ? 0 : 1;
}

static int cmd_join_otaa(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: join-otaa requires raw Join-Request hex string.\n");
        return 1;
    }

    const char *raw_hex = argv[2];
    const char *app_key_hex = NULL;
    const char *join_nonce_hex = "010203";
    const char *net_id_hex = "000001";
    const char *dev_addr_hex = "00112233";

    for (int i = 3; i < argc; i++) {
        if (strncmp(argv[i], "--app-key=", 10) == 0) {
            app_key_hex = argv[i] + 10;
        } else if (strncmp(argv[i], "--join-nonce=", 13) == 0) {
            join_nonce_hex = argv[i] + 13;
        } else if (strncmp(argv[i], "--net-id=", 9) == 0) {
            net_id_hex = argv[i] + 9;
        } else if (strncmp(argv[i], "--dev-addr=", 11) == 0) {
            dev_addr_hex = argv[i] + 11;
        }
    }

    if (!app_key_hex) {
        fprintf(stderr, "Error: --app-key=<32-hex> is mandatory for OTAA join verification.\n");
        return 1;
    }

    uint8_t raw[64];
    size_t raw_len = 0;
    if (!hex_to_bytes(raw_hex, raw, sizeof(raw), &raw_len) || raw_len != 23) {
        fprintf(stderr, "Error: invalid Join-Request hex string (must decode to exactly 23 bytes, got %zu).\n", raw_len);
        return 1;
    }

    uint8_t app_key[16];
    size_t key_len = 0;
    if (!hex_to_bytes(app_key_hex, app_key, sizeof(app_key), &key_len) || key_len != 16) {
        fprintf(stderr, "Error: invalid AppKey hex string (must decode to 16 bytes).\n");
        return 1;
    }

    uint8_t join_nonce[3];
    size_t jn_len = 0;
    if (!hex_to_bytes(join_nonce_hex, join_nonce, sizeof(join_nonce), &jn_len) || jn_len != 3) {
        fprintf(stderr, "Error: invalid JoinNonce hex string (must decode to 3 bytes).\n");
        return 1;
    }

    uint8_t net_id[3];
    size_t nid_len = 0;
    if (!hex_to_bytes(net_id_hex, net_id, sizeof(net_id), &nid_len) || nid_len != 3) {
        fprintf(stderr, "Error: invalid NetID hex string (must decode to 3 bytes).\n");
        return 1;
    }

    uint32_t dev_addr = (uint32_t)strtoul(dev_addr_hex, NULL, 16);

    lorawan_session_t session;
    lorawan_init_session(&session, NULL, dev_addr);

    uint8_t ja_out[32];
    size_t ja_len = 0;

    lora_error_t res = lorawan_process_join_request(
        raw, raw_len, app_key, join_nonce, net_id, dev_addr,
        &session, ja_out, &ja_len
    );

    lorawan_join_request_t req;
    lorawan_parse_join_request(raw, raw_len, &req);

    export_join_request_info(&req, (res == LORA_OK), dev_addr, session.nwk_skey, session.app_skey, stdout);

    if (res != LORA_OK) {
        fprintf(stderr, "Join verification failed: %s (%d)\n", lora_error_to_str(res), res);
        return 1;
    }

    return 0;
}

static int cmd_verify_uplink(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Error: verify-uplink requires raw uplink hex string.\n");
        return 1;
    }

    const char *raw_hex = argv[2];
    const char *nwk_skey_hex = NULL;
    const char *app_skey_hex = NULL;
    const char *dev_addr_hex = NULL;
    int fcnt = 0;
    double freq = 865.0625;
    const char *region_str = "IN865";

    for (int i = 3; i < argc; i++) {
        if (strncmp(argv[i], "--nwk-skey=", 11) == 0) {
            nwk_skey_hex = argv[i] + 11;
        } else if (strncmp(argv[i], "--app-skey=", 11) == 0) {
            app_skey_hex = argv[i] + 11;
        } else if (strncmp(argv[i], "--dev-addr=", 11) == 0) {
            dev_addr_hex = argv[i] + 11;
        } else if (strncmp(argv[i], "--fcnt=", 7) == 0) {
            fcnt = atoi(argv[i] + 7);
        } else if (strncmp(argv[i], "--freq=", 7) == 0) {
            freq = atof(argv[i] + 7);
        } else if (strncmp(argv[i], "--region=", 9) == 0) {
            region_str = argv[i] + 9;
        }
    }

    if (!nwk_skey_hex || !app_skey_hex || !dev_addr_hex) {
        fprintf(stderr, "Error: --nwk-skey, --app-skey, and --dev-addr are required.\n");
        return 1;
    }

    uint8_t raw[256];
    size_t raw_len = 0;
    if (!hex_to_bytes(raw_hex, raw, sizeof(raw), &raw_len) || raw_len < 12) {
        fprintf(stderr, "Error: invalid uplink hex string.\n");
        return 1;
    }

    uint8_t nwk_skey[16], app_skey[16];
    size_t klen1 = 0, klen2 = 0;
    if (!hex_to_bytes(nwk_skey_hex, nwk_skey, 16, &klen1) || klen1 != 16 ||
        !hex_to_bytes(app_skey_hex, app_skey, 16, &klen2) || klen2 != 16) {
        fprintf(stderr, "Error: invalid session keys (must decode to 16 bytes each).\n");
        return 1;
    }

    uint32_t dev_addr = (uint32_t)strtoul(dev_addr_hex, NULL, 16);

    lora_region_t region = lorawan_str_to_region(region_str);

    lorawan_session_t session;
    lorawan_init_session(&session, NULL, dev_addr);
    memcpy(session.nwk_skey, nwk_skey, 16);
    memcpy(session.app_skey, app_skey, 16);
    session.last_fcnt_up = (uint32_t)fcnt;
    session.has_fcnt_up = (fcnt > 0);
    session.is_active = true;

    lorawan_uplink_frame_t frame;
    uint8_t dec_payload[256];
    size_t dec_len = 0;

    lora_error_t res = lorawan_verify_and_decrypt_uplink(
        raw, raw_len, freq, region, &session, &frame, dec_payload, &dec_len
    );

    export_uplink_frame_info(&frame, (res == LORA_OK), dec_payload, dec_len, stdout);

    if (res != LORA_OK) {
        fprintf(stderr, "Uplink verification failed: %s (%d)\n", lora_error_to_str(res), res);
        return 1;
    }

    return 0;
}

static int cmd_calc_toa(int argc, char **argv) {
    lora_toa_params_t params;
    memset(&params, 0, sizeof(params));
    params.sf = 7;
    params.bw_khz = 125.0;
    params.cr = 1;
    params.payload_bytes = 16;
    params.preamble_symbols = 8;
    params.explicit_header = true;
    params.low_dr_opt = false;
    params.crc_enabled = true;
    params.region = REGION_IN865;

    const char *format = "table";

    for (int i = 2; i < argc; i++) {
        if (strncmp(argv[i], "--sf=", 5) == 0) {
            params.sf = atoi(argv[i] + 5);
        } else if (strncmp(argv[i], "--bw=", 5) == 0) {
            params.bw_khz = atof(argv[i] + 5);
        } else if (strncmp(argv[i], "--cr=", 5) == 0) {
            params.cr = atoi(argv[i] + 5);
        } else if (strncmp(argv[i], "--payload=", 10) == 0) {
            params.payload_bytes = (size_t)atoi(argv[i] + 10);
        } else if (strncmp(argv[i], "--preamble=", 11) == 0) {
            params.preamble_symbols = atoi(argv[i] + 11);
        } else if (strncmp(argv[i], "--region=", 9) == 0) {
            params.region = lorawan_str_to_region(argv[i] + 9);
        } else if (strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
        }
    }

    /* Auto Low Data Rate Optimization if symbol duration > 16ms */
    if (params.sf >= 11 && params.bw_khz <= 125.0) {
        params.low_dr_opt = true;
    }

    lora_toa_result_t result;
    lora_calculate_toa(&params, &result);

    if (strcmp(format, "json") == 0) {
        export_toa_json(&params, &result, stdout);
    } else {
        export_toa_table(&params, &result, stdout);
    }

    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "--version") == 0 || strcmp(cmd, "-v") == 0) {
        print_version();
        return 0;
    }

    if (strcmp(cmd, "--help") == 0 || strcmp(cmd, "-h") == 0) {
        print_help(argv[0]);
        return 0;
    }

    if (strcmp(cmd, "audit") == 0 || strcmp(cmd, "scan") == 0) {
        return cmd_audit(argc, argv);
    } else if (strcmp(cmd, "join-otaa") == 0) {
        return cmd_join_otaa(argc, argv);
    } else if (strcmp(cmd, "verify-uplink") == 0) {
        return cmd_verify_uplink(argc, argv);
    } else if (strcmp(cmd, "calc-toa") == 0) {
        return cmd_calc_toa(argc, argv);
    }

    fprintf(stderr, "Unknown command '%s'. Run '%s --help' for usage.\n", cmd, argv[0]);
    return 1;
}
