// SPDX-License-Identifier: MIT
//
// netlink_route.c -- SRv6 local SID management via RTNETLINK
//
// Installs/removes SRv6 local SIDs (seg6local) in the kernel routing table.
// This is what the PCC does with a path computed by the PCE: program each
// SRv6-ERO SID as a local behavior (End / End.X / uN / uA).
//
// Wire equivalent:
//   ip -6 route add <sid> encap seg6local action <behavior> [nh6 <nh>]
//          [flavors next-csid lblen <b> nflen <n>] dev <oif>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/lwtunnel.h>
#include <linux/seg6_local.h>
#include <linux/ipv6.h>
#include <linux/seg6.h> //本構成における
#include <linux/seg6_iptunnel.h> //本構成における
#include "netlink_route.h"

// Maximum Netlink message buffer
#define NL_BUF_SIZE 4096

// Helper: append a Netlink attribute
static int nl_addattr(struct nlmsghdr *n, int maxlen,
                      int type, const void *data, int alen)
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta;

    if ((int)(NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len)) > maxlen) {
        fprintf(stderr, "[nl_route] Message too large\n");
        return -1;
    }
    rta = (struct rtattr *)((uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len  = len;
    if (alen && data)
        memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    return 0;
}

// Helper: start a nested attribute, return pointer to its rtattr
static struct rtattr *nl_nest_start(struct nlmsghdr *n, int maxlen, int type)
{
    struct rtattr *nest = (struct rtattr *)
        ((uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len));
    nl_addattr(n, maxlen, type, NULL, 0);
    return nest;
}

// Helper: close a nested attribute
static void nl_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
    nest->rta_len = (uint8_t *)n + NLMSG_ALIGN(n->nlmsg_len) - (uint8_t *)nest;
}

// Open a NETLINK_ROUTE socket, send the message, and read the ACK.
static int nl_send_and_ack(struct nlmsghdr *nlh)
{
    int nlfd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (nlfd < 0) {
        perror("[nl_route] socket");
        return -1;
    }

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    if (bind(nlfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("[nl_route] bind");
        close(nlfd);
        return -1;
    }

    if (send(nlfd, nlh, nlh->nlmsg_len, 0) < 0) {
        perror("[nl_route] send");
        close(nlfd);
        return -1;
    }

    uint8_t ack_buf[256];
    int ack_len = recv(nlfd, ack_buf, sizeof(ack_buf), 0);
    close(nlfd);

    if (ack_len < 0) {
        perror("[nl_route] recv ack");
        return -1;
    }

    struct nlmsghdr *ack = (struct nlmsghdr *)ack_buf;
    if (ack->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(ack);
        if (err->error != 0) {
            errno = -err->error;
            perror("[nl_route] RTM operation failed");
            return -1;
        }
    }
    return 0;
}

// Map an SRv6 endpoint behavior to a kernel seg6local action id.
static int behavior_to_action(uint16_t behavior, int *needs_nh, int *needs_csid)
{
    *needs_nh = 0;
    *needs_csid = 0;
    switch (behavior) {
    case SRV6_BEHAVIOR_END:
        return SEG6_LOCAL_ACTION_END;
    case SRV6_BEHAVIOR_END_X:
        *needs_nh = 1;
        return SEG6_LOCAL_ACTION_END_X;
    case SRV6_BEHAVIOR_UN:
        *needs_csid = 1;
        return SEG6_LOCAL_ACTION_END;
    case SRV6_BEHAVIOR_UA:
        *needs_nh = 1;
        *needs_csid = 1;
        return SEG6_LOCAL_ACTION_END_X;
    default:
        return -1;
    }
}

int netlink_add_srv6_local_sid(const struct in6_addr *sid, int prefix_len,
                               uint16_t behavior,
                               const struct in6_addr *nh6,
                               const char *oif_name,
                               int lcblock_bits, int lcnode_bits)
{
    int needs_nh, needs_csid;
    int action = behavior_to_action(behavior, &needs_nh, &needs_csid);
    if (action < 0) {
        fprintf(stderr, "[nl_route] Unsupported SRv6 behavior 0x%04x\n", behavior);
        return -1;
    }
    if (needs_nh && !nh6) {
        fprintf(stderr, "[nl_route] Behavior 0x%04x requires a next-hop (NAI missing)\n",
                behavior);
        return -1;
    }

    char sid_str[64];
    inet_ntop(AF_INET6, sid, sid_str, sizeof(sid_str));
    printf("[nl_route] Installing local SID %s/%d behavior=0x%04x action=%d%s\n",
           sid_str, prefix_len, behavior, action, needs_csid ? " (next-csid)" : "");

    uint8_t buf[NL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family   = AF_INET6;
    rtm->rtm_dst_len  = (uint8_t)prefix_len;
    rtm->rtm_table    = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_type     = RTN_UNICAST;
    rtm->rtm_scope    = RT_SCOPE_UNIVERSE;

    if (nl_addattr(nlh, sizeof(buf), RTA_DST, sid, sizeof(*sid)) < 0)
        return -1;

    uint16_t encap_type = LWTUNNEL_ENCAP_SEG6_LOCAL;
    if (nl_addattr(nlh, sizeof(buf), RTA_ENCAP_TYPE,
                   &encap_type, sizeof(encap_type)) < 0)
        return -1;

    // RTA_ENCAP -> { SEG6_LOCAL_ACTION, [NH6], [FLAVORS] }
    struct rtattr *encap = nl_nest_start(nlh, sizeof(buf), RTA_ENCAP);
    if (!encap) return -1;

    uint32_t action32 = (uint32_t)action;
    if (nl_addattr(nlh, sizeof(buf), SEG6_LOCAL_ACTION,
                   &action32, sizeof(action32)) < 0)
        return -1;

    if (needs_nh) {
        if (nl_addattr(nlh, sizeof(buf), SEG6_LOCAL_NH6, nh6, sizeof(*nh6)) < 0)
            return -1;
    }

    if (needs_csid) {
        // SEG6_LOCAL_FLAVORS -> { FLV_OPERATION, LCBLOCK_BITS, LCNODE_FN_BITS }
        struct rtattr *flv = nl_nest_start(nlh, sizeof(buf), SEG6_LOCAL_FLAVORS);
        if (!flv) return -1;

        uint32_t flv_ops = (1u << SEG6_LOCAL_FLV_OP_NEXT_CSID);
        if (nl_addattr(nlh, sizeof(buf), SEG6_LOCAL_FLV_OPERATION,
                       &flv_ops, sizeof(flv_ops)) < 0)
            return -1;

        uint8_t lcb = (uint8_t)(lcblock_bits > 0 ? lcblock_bits : USID_DEFAULT_LCBLOCK_BITS);
        uint8_t lcn = (uint8_t)(lcnode_bits  > 0 ? lcnode_bits  : USID_DEFAULT_LCNODE_FN_BITS);
        if (nl_addattr(nlh, sizeof(buf), SEG6_LOCAL_FLV_LCBLOCK_BITS,
                       &lcb, sizeof(lcb)) < 0)
            return -1;
        if (nl_addattr(nlh, sizeof(buf), SEG6_LOCAL_FLV_LCNODE_FN_BITS,
                       &lcn, sizeof(lcn)) < 0)
            return -1;

        nl_nest_end(nlh, flv);
    }

    nl_nest_end(nlh, encap);

    // Route output device (mandatory for encap routes, like iproute2 "dev")
    if (oif_name) {
        uint32_t oif = if_nametoindex(oif_name);
        if (oif == 0) {
            fprintf(stderr, "[nl_route] Unknown interface '%s'\n", oif_name);
            return -1;
        }
        if (nl_addattr(nlh, sizeof(buf), RTA_OIF, &oif, sizeof(oif)) < 0)
            return -1;
    }

    int ret = nl_send_and_ack(nlh);
    if (ret == 0)
        printf("[nl_route] Local SID installed successfully\n");
    return ret;
}

int netlink_del_srv6_route(const struct in6_addr *dst, int prefix_len)
{
    char dst_str[64];
    inet_ntop(AF_INET6, dst, dst_str, sizeof(dst_str));
    printf("[nl_route] Deleting route %s/%d\n", dst_str, prefix_len);

    uint8_t buf[NL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq   = 1;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family  = AF_INET6;
    rtm->rtm_dst_len = (uint8_t)prefix_len;
    rtm->rtm_table   = RT_TABLE_MAIN;
    rtm->rtm_scope   = RT_SCOPE_UNIVERSE;

    if (nl_addattr(nlh, sizeof(buf), RTA_DST, dst, sizeof(*dst)) < 0)
        return -1;

    return nl_send_and_ack(nlh);
}


//本構成における
int netlink_add_srv6_encap_table(uint32_t table_id,
                                 const struct in6_addr *sids, int sid_count,
                                 const char *oif_name)
{
    if (sid_count <= 0) return -1;

    uint8_t buf[NL_BUF_SIZE];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type  = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq   = 2;
    nlh->nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));

    struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nlh);
    rtm->rtm_family   = AF_INET;
    rtm->rtm_dst_len  = 24; // 192.168.2.0/24
    rtm->rtm_table    = (table_id < 256) ? (uint8_t)table_id : RT_TABLE_UNSPEC;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_type     = RTN_UNICAST;
    rtm->rtm_scope    = RT_SCOPE_UNIVERSE;

    struct in_addr dst4;
    inet_pton(AF_INET, "192.168.2.0", &dst4);
    nl_addattr(nlh, sizeof(buf), RTA_DST, &dst4, sizeof(dst4));
    nl_addattr(nlh, sizeof(buf), RTA_TABLE, &table_id, sizeof(table_id));

    uint16_t encap_type = LWTUNNEL_ENCAP_SEG6;
    nl_addattr(nlh, sizeof(buf), RTA_ENCAP_TYPE, &encap_type, sizeof(encap_type));

    struct rtattr *encap = nl_nest_start(nlh, sizeof(buf), RTA_ENCAP);
    size_t srh_len = sizeof(struct ipv6_sr_hdr) + sid_count * sizeof(struct in6_addr);
    size_t tun_len = sizeof(struct seg6_iptunnel_encap) + srh_len;
    struct seg6_iptunnel_encap *tun = calloc(1, tun_len);

    tun->mode = SEG6_IPTUN_MODE_ENCAP;
    struct ipv6_sr_hdr *srh = tun->srh;
    srh->hdrlen        = (uint8_t)((srh_len >> 3) - 1);
    srh->type          = 4;
    srh->segments_left = (uint8_t)(sid_count - 1);
    srh->first_segment = (uint8_t)(sid_count - 1);

    for (int i = 0; i < sid_count; i++) {
        srh->segments[sid_count - 1 - i] = sids[i];
    }

    nl_addattr(nlh, sizeof(buf), SEG6_IPTUNNEL_SRH, tun, (int)tun_len);
    free(tun);
    nl_nest_end(nlh, encap);

    const char *ifname = (oif_name && oif_name[0]) ? oif_name : "eth1";
    uint32_t oif = if_nametoindex(ifname);
    if (oif > 0) nl_addattr(nlh, sizeof(buf), RTA_OIF, &oif, sizeof(oif));

    printf("[nl_route] Installed SRv6 Policy to Table %u (dst=192.168.2.0/24, %d SIDs)\n",
           table_id, sid_count);
    return nl_send_and_ack(nlh);
}