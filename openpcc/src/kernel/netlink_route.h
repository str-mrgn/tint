// SPDX-License-Identifier: MIT
#ifndef NETLINK_ROUTE_H
#define NETLINK_ROUTE_H

#include <stdint.h>
#include <netinet/in.h>

// Delete an IPv6 route from the routing table via Netlink.
// Equivalent to: ip -6 route del <dst>/<pfx>
int netlink_del_srv6_route(const struct in6_addr *dst, int prefix_len);

// SRv6 endpoint behaviors carried in the PCEP SRv6-ERO subobject
// (values from IANA "SRv6 Endpoint Behaviors" registry, as emitted by Pola).
#define SRV6_BEHAVIOR_END    0x0001  // End
#define SRV6_BEHAVIOR_END_X  0x0005  // End.X (L3 cross-connect)
#define SRV6_BEHAVIOR_UN     0x0030  // uN  (End w/ NEXT-CSID)
#define SRV6_BEHAVIOR_UA     0x0039  // uA  (End.X w/ NEXT-CSID)

// Default uSID (NEXT-CSID) locator layout: 32-bit block + 16-bit node function
#define USID_DEFAULT_LCBLOCK_BITS   32
#define USID_DEFAULT_LCNODE_FN_BITS 16

// Instantiate a local SRv6 SID in the kernel via Netlink (seg6local encap).
//
// sid:          local SID address to program
// prefix_len:   prefix length of the SID route (usually 128, or the
//               locator-block+node length for uSID)
// behavior:     one of SRV6_BEHAVIOR_* above
// nh6:          IPv6 next-hop for End.X / uA (NULL for End / uN)
// oif_name:     output interface (may be NULL)
// lcblock_bits: uSID locator-block length in bits (uN/uA only)
// lcnode_bits:  uSID node-function length in bits (uN/uA only)
//
// Equivalent to, e.g.:
//   ip -6 route add <sid> encap seg6local action End dev <oif>
//   ip -6 route add <sid> encap seg6local action End.X nh6 <nh> dev <oif>
//   ip -6 route add <sid> encap seg6local action End
//          flavors next-csid lblen <b> nflen <n> dev <oif>
int netlink_add_srv6_local_sid(const struct in6_addr *sid, int prefix_len,
                               uint16_t behavior,
                               const struct in6_addr *nh6,
                               const char *oif_name,
                               int lcblock_bits, int lcnode_bits);

//本構成における                               
int netlink_add_srv6_encap_table(uint32_t table_id,
                                 const struct in6_addr *sids, int sid_count,
                                 const char *oif_name);                               
#endif /* NETLINK_ROUTE_H */
