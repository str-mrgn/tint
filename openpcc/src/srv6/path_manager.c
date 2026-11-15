// SPDX-License-Identifier: MIT
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include "../../include/srv6_pcc.h"
#include "../types/common.h"
#include "../kernel/netlink_route.h"
#include "path_manager.h"

// ----- PCEP wire constants -----
#define OT_ERO_SRV6_SUBOBJ   40      // SRv6-ERO subobject type (RFC 9603)
#define NT_SRV6_NODE          2      // NAI: SRv6 node
#define NT_SRV6_ADJ_GLOBAL    4      // NAI: SRv6 adjacency (global)

#define TLV_SYMBOLIC_PATH_NAME  0x11 // RFC 8231
#define TLV_PATH_SETUP_TYPE     0x1c // RFC 8408
#define PST_SRV6_TE             3    // Path-Setup-Type = SRv6-TE

// LSP object flag bits (matching Pola's on-wire layout, byte 3 of body)
#define LSP_FLAG_C  0x80
#define LSP_FLAG_A  0x08
#define LSP_FLAG_R  0x04
#define LSP_FLAG_S  0x02
#define LSP_FLAG_D  0x01

// Local configuration
static char g_oif[IF_NAMESIZE] = "";
static int  g_lcblock_bits = USID_DEFAULT_LCBLOCK_BITS;
static int  g_lcnode_bits  = USID_DEFAULT_LCNODE_FN_BITS;

// Parsed segment / LSP state
struct parsed_sid {
    struct in6_addr sid;
    uint16_t        behavior;
    int             has_nh;
    struct in6_addr nh6;
};

struct lsp_entry {
    int             used;
    uint32_t        plsp_id;
    char            name[64];
    struct in6_addr dst;
    int             have_dst;
    struct parsed_sid sids[MAX_SID_LIST_SIZE];
    int             sid_count;
};

#define MAX_LSPS 64
static struct lsp_entry g_lsps[MAX_LSPS];
static uint32_t g_next_plsp = 1;

// Parsed view of an incoming PCInitiate / PCUpdate message
struct pcep_parsed {
    int      have_srp;
    uint32_t srp_id;
    int      srp_remove;

    int      have_lsp;
    uint32_t plsp_id;
    int      lsp_remove;
    char     name[64];

    int             have_dst;
    struct in6_addr dst;

    struct parsed_sid sids[MAX_SID_LIST_SIZE];
    int               sid_count;

    const uint8_t *ero_raw;   // raw ERO object (incl. header), for PCRpt echo
    int            ero_raw_len;
};

static inline uint16_t get_u16be(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}
static inline uint32_t get_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}
static inline void put_u16be(uint8_t *p, uint16_t v)
{
    p[0] = (v >> 8) & 0xff;
    p[1] =  v       & 0xff;
}
static inline void put_u32be(uint8_t *p, uint32_t v)
{
    p[0] = (v >> 24) & 0xff; p[1] = (v >> 16) & 0xff;
    p[2] = (v >>  8) & 0xff; p[3] =  v        & 0xff;
}

int path_manager_init(const char *oif_name, int lcblock_bits, int lcnode_bits)
{
    memset(g_lsps, 0, sizeof(g_lsps));
    g_oif[0] = '\0';
    if (oif_name)
        strncpy(g_oif, oif_name, sizeof(g_oif) - 1);
    if (lcblock_bits > 0) g_lcblock_bits = lcblock_bits;
    if (lcnode_bits  > 0) g_lcnode_bits  = lcnode_bits;

    printf("[path_mgr] Initialized: oif=%s uSID lblen=%d nflen=%d\n",
           g_oif[0] ? g_oif : "(none)", g_lcblock_bits, g_lcnode_bits);
    return 0;
}

// Parse the SYMBOLIC-PATH-NAME TLV out of an LSP object body (after PLSP word).
static void parse_lsp_tlvs(const uint8_t *tlvs, int len, char *name, int name_sz)
{
    int off = 0;
    while (off + 4 <= len) {
        uint16_t t = get_u16be(tlvs + off);
        uint16_t l = get_u16be(tlvs + off + 2);
        if (off + 4 + l > len) break;
        if (t == TLV_SYMBOLIC_PATH_NAME) {
            int n = l < (name_sz - 1) ? l : (name_sz - 1);
            memcpy(name, tlvs + off + 4, n);
            name[n] = '\0';
        }
        int step = 4 + l;
        if (step % 4) step += 4 - (step % 4);   // 4-byte alignment
        off += step;
    }
}

// Parse the SRv6 subobjects of an ERO object body into out->sids.
static void parse_ero_subobjects(const uint8_t *body, int len,
                                 struct pcep_parsed *out)
{
    int off = 0;
    while (off + 2 <= len) {
        uint8_t stype = body[off] & 0x7f;
        uint8_t slen  = body[off + 1];
        if (slen < 2 || off + slen > len) break;

        if (stype == OT_ERO_SRV6_SUBOBJ && slen >= 24 &&
            out->sid_count < MAX_SID_LIST_SIZE) {
            const uint8_t *s = body + off;
            struct parsed_sid *ps = &out->sids[out->sid_count];
            memset(ps, 0, sizeof(*ps));

            ps->behavior = get_u16be(s + 6);       // Endpoint Behavior
            memcpy(&ps->sid, s + 8, 16);           // SRv6-SID (128 bit)

            uint8_t nt = s[2] >> 4;                // NAI type
            if (nt == NT_SRV6_ADJ_GLOBAL && slen >= 56) {
                // local(16) @24, remote(16) @40 -> remote is the next-hop
                memcpy(&ps->nh6, s + 40, 16);
                ps->has_nh = 1;
            }

            char sid_str[64], nh_str[64];
            inet_ntop(AF_INET6, &ps->sid, sid_str, sizeof(sid_str));
            if (ps->has_nh) {
                inet_ntop(AF_INET6, &ps->nh6, nh_str, sizeof(nh_str));
                printf("[path_mgr] SRv6-ERO[%d] sid=%s behavior=0x%04x nh=%s\n",
                       out->sid_count, sid_str, ps->behavior, nh_str);
            } else {
                printf("[path_mgr] SRv6-ERO[%d] sid=%s behavior=0x%04x\n",
                       out->sid_count, sid_str, ps->behavior);
            }
            out->sid_count++;
        }
        off += slen;
    }
}

static int parse_message(const uint8_t *buf, int len, struct pcep_parsed *out)
{
    memset(out, 0, sizeof(*out));

    const uint8_t *p = buf + sizeof(struct pcep_common_header);
    int rem = len - (int)sizeof(struct pcep_common_header);

    while (rem >= (int)sizeof(struct pcep_object_header)) {
        const struct pcep_object_header *oh = (const struct pcep_object_header *)p;
        uint16_t obj_len = get_u16be((const uint8_t *)&oh->length);
        if (obj_len < sizeof(struct pcep_object_header) || obj_len > rem)
            break;

        uint8_t oclass = oh->object_class;
        uint8_t otype  = oh->ot_flags >> 4;
        const uint8_t *body = p + sizeof(struct pcep_object_header);
        int body_len = obj_len - (int)sizeof(struct pcep_object_header);

        switch (oclass) {
        case PCEP_OBJ_SRP:   // 33: flags(4) + srp-id(4) + TLVs
            if (body_len >= 8) {
                out->have_srp   = 1;
                out->srp_remove = (body[3] & 0x01) != 0;
                out->srp_id     = get_u32be(body + 4);
            }
            break;

        case PCEP_OBJ_LSP:   // 32: plsp(20)|flags(12) + TLVs
            if (body_len >= 4) {
                out->have_lsp    = 1;
                out->plsp_id     = get_u32be(body) >> 12;
                out->lsp_remove  = (body[3] & LSP_FLAG_R) != 0;
                if (body_len > 4)
                    parse_lsp_tlvs(body + 4, body_len - 4,
                                   out->name, sizeof(out->name));
            }
            break;

        case PCEP_OBJ_ENDPOINTS:  
            if (otype == 2 && body_len >= 32) {
                memcpy(&out->dst, body + 16, 16);
                out->have_dst = 1;
            }
            break;

        case PCEP_OBJ_ERO:   
            out->ero_raw     = p;
            out->ero_raw_len = obj_len;
            parse_ero_subobjects(body, body_len, out);
            break;

        default:
            break;   
        }

        p   += obj_len;
        rem -= obj_len;
    }
    return 0;
}

// kernel application

static int install_sid(const struct parsed_sid *ps)
{
    int prefix_len = 128;
    const struct in6_addr *nh = ps->has_nh ? &ps->nh6 : NULL;
    int lcb = 0, lcn = 0;

    if (ps->behavior == SRV6_BEHAVIOR_UN || ps->behavior == SRV6_BEHAVIOR_UA) {
        // uSID behaviors match on the locator (block + node function) prefix
        prefix_len = g_lcblock_bits + g_lcnode_bits;
        lcb = g_lcblock_bits;
        lcn = g_lcnode_bits;
    }
    return netlink_add_srv6_local_sid(&ps->sid, prefix_len, ps->behavior,
                                      nh, g_oif[0] ? g_oif : NULL, lcb, lcn);
}

static void withdraw_sid(const struct parsed_sid *ps)
{
    int prefix_len = 128;
    if (ps->behavior == SRV6_BEHAVIOR_UN || ps->behavior == SRV6_BEHAVIOR_UA)
        prefix_len = g_lcblock_bits + g_lcnode_bits;
    netlink_del_srv6_route(&ps->sid, prefix_len);
}

// LSP table

static struct lsp_entry *lsp_find(uint32_t plsp_id)
{
    for (int i = 0; i < MAX_LSPS; i++)
        if (g_lsps[i].used && g_lsps[i].plsp_id == plsp_id)
            return &g_lsps[i];
    return NULL;
}

static struct lsp_entry *lsp_alloc(void)
{
    for (int i = 0; i < MAX_LSPS; i++)
        if (!g_lsps[i].used)
            return &g_lsps[i];
    return NULL;
}

static void lsp_withdraw_all(struct lsp_entry *e)
{
    for (int i = 0; i < e->sid_count; i++)
        withdraw_sid(&e->sids[i]);
}

// Install every SID of a parsed message into an LSP entry.
//本構成における
static int lsp_apply(struct lsp_entry *e, const struct pcep_parsed *pp)
{
    int errors = 0;
    e->sid_count = 0;
    struct in6_addr sid_list[MAX_SID_LIST_SIZE];
    for (int i = 0; i < pp->sid_count; i++) {
        e->sids[e->sid_count] = pp->sids[i];
        sid_list[e->sid_count] = pp->sids[i].sid;
        e->sid_count++;
    }

    // 決め打ち: 1本目(PLSP-ID 1)は Table 100、2本目(PLSP-ID 2)は Table 200 に登録
    uint32_t target_table = (e->plsp_id == 1) ? 100 : 200;
    if (netlink_add_srv6_encap_table(target_table, sid_list, e->sid_count, g_oif) != 0)
        errors++;

    strncpy(e->name, pp->name, sizeof(e->name) - 1);
    e->name[sizeof(e->name) - 1] = '\0';
    if (pp->have_dst) {
        e->dst = pp->dst;
        e->have_dst = 1;
    }
    return errors ? -1 : 0;
}

// PCRpt

static int send_pcrpt(uint32_t srp_id, uint32_t plsp_id, const char *name,
                      const uint8_t *ero_raw, int ero_raw_len, int remove)
{
    uint8_t buf[2048];
    int pos = sizeof(struct pcep_common_header);   // fill header last

    int srp_start = pos;
    buf[pos++] = PCEP_OBJ_SRP;
    buf[pos++] = (1 << 4) | (1 << 1);              // OT=1, P=1
    pos += 2;                                      // length later
    put_u32be(&buf[pos], remove ? 0x00000001 : 0); pos += 4;   // flags (R)
    put_u32be(&buf[pos], srp_id);                  pos += 4;   // SRP-ID
    // PATH-SETUP-TYPE TLV = SRv6-TE
    put_u16be(&buf[pos], TLV_PATH_SETUP_TYPE); pos += 2;
    put_u16be(&buf[pos], 4);                   pos += 2;
    buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = PST_SRV6_TE;
    put_u16be(&buf[srp_start + 2], (uint16_t)(pos - srp_start));

    // LSP object
    int lsp_start = pos;
    buf[pos++] = PCEP_OBJ_LSP;
    buf[pos++] = (1 << 4) | (1 << 1);              // OT=1, P=1
    pos += 2;                                      // length later
    uint8_t flags = LSP_FLAG_C | LSP_FLAG_A | LSP_FLAG_D;  // create, admin-up, delegate
    flags |= (1 << 4);                             // O = 1 (operational UP)
    if (remove) flags |= LSP_FLAG_R;
    put_u32be(&buf[pos], (plsp_id << 12));         // PLSP-ID in top 20 bits
    buf[pos + 3] = flags;                          // low byte = flags/O
    pos += 4;
    // SYMBOLIC-PATH-NAME TLV
    {
        const char *nm = (name && name[0]) ? name : "pcc-lsp";
        uint16_t nl = (uint16_t)strlen(nm);
        put_u16be(&buf[pos], TLV_SYMBOLIC_PATH_NAME); pos += 2;
        put_u16be(&buf[pos], nl);                     pos += 2;
        memcpy(&buf[pos], nm, nl);                    pos += nl;
        while (pos % 4) buf[pos++] = 0;               // pad to 4 bytes
    }
    put_u16be(&buf[lsp_start + 2], (uint16_t)(pos - lsp_start));

    // ERO object
    if (!remove && ero_raw && ero_raw_len > 0 &&
        pos + ero_raw_len <= (int)sizeof(buf)) {
        memcpy(&buf[pos], ero_raw, ero_raw_len);
        pos += ero_raw_len;
    }

    // PCEP common header
    struct pcep_common_header *hdr = (struct pcep_common_header *)buf;
    hdr->ver_flags    = (PCEP_VERSION << 5);
    hdr->message_type = PCEP_MSG_PCRPT;
    put_u16be((uint8_t *)&hdr->message_length, (uint16_t)pos);

    printf("[path_mgr] Sending PCRpt (plsp=%u srp=%u%s, len=%d)\n",
           plsp_id, srp_id, remove ? " remove" : "", pos);
    return pcc_send_raw(buf, pos);
}

// message handlers

int path_manager_handle_pcinitiate(const uint8_t *buf, int len)
{
    struct pcep_parsed pp;
    parse_message(buf, len, &pp);

    int is_remove = pp.srp_remove || pp.lsp_remove;

    if (is_remove) {
        struct lsp_entry *e = lsp_find(pp.plsp_id);
        if (!e) {
            printf("[path_mgr] PCInitiate remove for unknown PLSP-ID %u\n", pp.plsp_id);
            return send_pcrpt(pp.srp_id, pp.plsp_id, pp.name, NULL, 0, 1);
        }
        printf("[path_mgr] PCInitiate remove: withdrawing %d SID(s) of PLSP-ID %u\n",
               e->sid_count, e->plsp_id);
        lsp_withdraw_all(e);
        uint32_t plsp = e->plsp_id;
        char name[64];
        strncpy(name, e->name, sizeof(name) - 1); name[sizeof(name) - 1] = '\0';
        memset(e, 0, sizeof(*e));
        return send_pcrpt(pp.srp_id, plsp, name, NULL, 0, 1);
    }

    if (pp.sid_count == 0) {
        printf("[path_mgr] PCInitiate without SRv6-ERO subobjects, nothing to install\n");
        return 0;
    }

    // PCE-initiated create
    struct lsp_entry *e = lsp_alloc();
    if (!e) {
        fprintf(stderr, "[path_mgr] LSP table full\n");
        return -1;
    }
    e->used    = 1;
    e->plsp_id = (pp.plsp_id != 0) ? pp.plsp_id : g_next_plsp++;

    printf("[path_mgr] PCInitiate create: PLSP-ID %u, installing %d SID(s)\n",
           e->plsp_id, pp.sid_count);
    lsp_apply(e, &pp);

    return send_pcrpt(pp.srp_id, e->plsp_id, e->name,
                      pp.ero_raw, pp.ero_raw_len, 0);
}

int path_manager_handle_pcupdate(const uint8_t *buf, int len)
{
    struct pcep_parsed pp;
    parse_message(buf, len, &pp);

    struct lsp_entry *e = lsp_find(pp.plsp_id);
    if (!e) {
        // Unknown LSP: treat as a fresh install so we still program the kernel.
        printf("[path_mgr] PCUpdate for unknown PLSP-ID %u, installing as new\n",
               pp.plsp_id);
        e = lsp_alloc();
        if (!e) {
            fprintf(stderr, "[path_mgr] LSP table full\n");
            return -1;
        }
        e->used    = 1;
        e->plsp_id = pp.plsp_id ? pp.plsp_id : g_next_plsp++;
    } else {
        printf("[path_mgr] PCUpdate: re-programming PLSP-ID %u (%d old SID(s))\n",
               e->plsp_id, e->sid_count);
        lsp_withdraw_all(e);   // remove previous SIDs before applying new ones
    }

    if (pp.sid_count == 0) {
        printf("[path_mgr] PCUpdate with empty ERO: LSP %u left with no SIDs\n",
               e->plsp_id);
        e->sid_count = 0;
    } else {
        printf("[path_mgr] PCUpdate: installing %d SID(s)\n", pp.sid_count);
        lsp_apply(e, &pp);
    }

    return send_pcrpt(pp.srp_id, e->plsp_id, e->name,
                      pp.ero_raw, pp.ero_raw_len, 0);
}
