#ifndef XDP_PROG_H
#define XDP_PROG_H
#include <linux/types.h>

#define ETH_ALEN 6

struct vlan_ethhdr {
  unsigned char h_dest[ETH_ALEN];
  unsigned char h_source[ETH_ALEN];
  __be16 h_vlan_proto;
  __be16 h_vlan_TCI;
  __be16 h_vlan_encapsulated_proto;
};

// tcp options
struct tcpopt {
  __u8 kind;
  __u8 len;
};

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */

#endif  // XDP_PROG_H
