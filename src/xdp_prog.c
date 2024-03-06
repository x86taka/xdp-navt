#include "xdp_prog.h"

#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

#include "bpf_endian.h"
#include "bpf_helpers.h"

static __always_inline void update_checksum(uint16_t *csum, uint16_t old_val,
                                            uint16_t new_val) {
  uint32_t new_csum_value;
  uint32_t new_csum_comp;
  uint32_t undo;

  undo = ~((uint32_t)*csum) + ~((uint32_t)old_val);
  new_csum_value = undo + (undo < ~((uint32_t)old_val)) + (uint32_t)new_val;
  new_csum_comp = new_csum_value + (new_csum_value < ((uint32_t)new_val));
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  new_csum_comp = (new_csum_comp & 0xFFFF) + (new_csum_comp >> 16);
  *csum = (uint16_t)~new_csum_comp;
}

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *ether_header;
  ether_header = data;

  if (data + sizeof(*ether_header) > data_end) {
    return XDP_ABORTED;
  }

  uint16_t h_proto = ether_header->h_proto;

  if (h_proto == htons(ETH_P_IPV6)) {  // Is IPv6 Packet
    return XDP_DROP;
  }

  if (ether_header->h_proto == htons(ETH_P_8021Q)) {
    struct vlan_ethhdr *vlan_header;
    vlan_header = data;
    if (data + sizeof(*vlan_header) > data_end) {
      return XDP_ABORTED;
    }
    // 運営からのpkt
    if (ntohs(vlan_header->h_vlan_TCI) == 0x051) {
      uint8_t dmac[6] = {0xbc, 0x24, 0x11,
                         0xbb, 0x1e, 0x31};  // VM用のL3のMAC BC:24:11:BB:1E:31
      __builtin_memcpy(&vlan_header->h_source, &vlan_header->h_dest,
                       sizeof(dmac));
      __builtin_memcpy(vlan_header->h_dest, dmac, sizeof(dmac));

      // IPv4 Packet
      if (vlan_header->h_vlan_encapsulated_proto == htons(ETH_P_IP)) {
        struct iphdr *ip_header;
        data += sizeof(*vlan_header);
        if (data + sizeof(*ip_header) > data_end) {
          return XDP_ABORTED;
        }

        ip_header = data;
        // dstIPからvlanIDのデータ取り出す
        __u16 daddr_to_vlan = ntohl(ip_header->daddr) >> 16;
        daddr_to_vlan = daddr_to_vlan << 8;
        daddr_to_vlan = daddr_to_vlan >> 8;

        int vlan = daddr_to_vlan;
        if (vlan == 0) {
          return XDP_DROP;
        }
        vlan = vlan * 100;
        daddr_to_vlan = (__u16)vlan;
        daddr_to_vlan = htons(daddr_to_vlan);
        __builtin_memcpy(&vlan_header->h_vlan_TCI, &daddr_to_vlan,
                         sizeof(__u16));

        __uint32_t daddr = ntohl(ip_header->daddr) << 16;
        daddr = daddr >> 16;
        daddr = htonl(0xC0A80000 | daddr);

        __u16 old_ip_2_octets = ntohl(ip_header->daddr) >> 16;
        __u16 new_ip_2_octets = ntohl(daddr) >> 16;
        update_checksum(&ip_header->check, htons(old_ip_2_octets),
                        htons(new_ip_2_octets));
        __builtin_memcpy(&ip_header->daddr, &daddr, sizeof(__uint32_t));
        if (ip_header->protocol == IPPROTO_TCP) {
          struct tcphdr *tcp_header;
          data += sizeof(*ip_header);
          if (data + sizeof(*tcp_header) > data_end) {
            return XDP_ABORTED;
          }
          tcp_header = data;
          update_checksum(&tcp_header->check, ntohs(old_ip_2_octets),
                          ntohs(new_ip_2_octets));
        }
        return XDP_TX;
      }
    }

    // vmからのpkt

    // VLAN IDの先頭2桁を取得
    __u16 vlan_id = ntohs(vlan_header->h_vlan_TCI) & VLAN_VID_MASK;
    __u16 first_two_digits = (vlan_id & 0xFF00) >> 8;
    int vlan_test = vlan_id;
    vlan_test = vlan_test / 100;
    if (vlan_test == 10) {
      // return XDP_DROP;
    }
    first_two_digits = (__u16)vlan_test;

    // set vlan id 81
    __u16 vlan_id_81 = htons(0x051);
    __builtin_memcpy(&vlan_header->h_vlan_TCI, &vlan_id_81, sizeof(__u16));
    uint8_t dmac[6] = {0xbc, 0x24, 0x11,
                       0xb0, 0x06, 0x80};  // 運営用のL3のMAC BC:24:11:B0:06:80
    __builtin_memcpy(&vlan_header->h_source, &vlan_header->h_dest,
                     sizeof(dmac));
    __builtin_memcpy(vlan_header->h_dest, dmac, sizeof(dmac));

    // IPv4 Packet
    if (vlan_header->h_vlan_encapsulated_proto == htons(ETH_P_IP)) {
      struct iphdr *ip_header;
      data += sizeof(*vlan_header);
      if (data + sizeof(*ip_header) > data_end) {
        return XDP_ABORTED;
      }

      ip_header = data;

      __uint32_t saddr = ntohl(ip_header->saddr) << 16;
      saddr = saddr >> 16;

      __uint32_t vlan_to_saddr = first_two_digits << 16 | 0x0A000000 | saddr;
      // csum
      __uint16_t old_two_octets = ntohl(ip_header->saddr) >> 16;
      __uint16_t new_two_octets = vlan_to_saddr >> 16;
      update_checksum(&ip_header->check, ntohs(old_two_octets),
                      ntohs(new_two_octets));
      vlan_to_saddr = htonl(vlan_to_saddr);
      __builtin_memcpy(&ip_header->saddr, &vlan_to_saddr, sizeof(__uint32_t));
      if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp_header;
        data += sizeof(*ip_header);
        if (data + sizeof(*tcp_header) > data_end) {
          return XDP_ABORTED;
        }
        tcp_header = data;
        update_checksum(&tcp_header->check, ntohs(old_two_octets),
                        ntohs(new_two_octets));
      }

      return XDP_TX;
    }
  }
  return XDP_PASS;
}

char __license[] SEC("license") = "Dual MIT/GPL";

/*
    169.     254.       1.      254      /24
1010 1001 1111 1110 0000 0001 1111 1110

169.254.0.254
0xA9FE02FE
*/
