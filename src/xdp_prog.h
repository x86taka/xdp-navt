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

// Configuration structures for eBPF maps
struct mac_config {
  __u8 my_mac[ETH_ALEN];
  __u8 to_upstream[ETH_ALEN];    // QFX VRF (upstream side)
  __u8 to_downstream[ETH_ALEN];  // QFX VLAN 98 (downstream side)
};

struct vlan_config {
  __u16 management_vlan;  // VLAN for management packets (0x062)
  __u16 output_vlan;      // Output VLAN (98)
};

struct ip_config {
  __u32 inside_network;   // Inside network base (192.168.0.0)
  __u32 outside_network;  // Outside network base (10.0.0.0)
};

#define VLAN_VID_MASK 0x0fff /* VLAN Identifier */

#endif  // XDP_PROG_H
