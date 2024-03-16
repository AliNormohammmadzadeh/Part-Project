#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define IP_ADDRESS(x,y) (unsigned int)(10 + (x << 8) + (5 << 16) + (y << 24))
#define MAX_MAP_ENTRIES 16
#define ICMP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, checksum))
#define ICMP_TYPE_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct icmphdr, type))

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_MAP_ENTRIES);
  __type(key, __u32);
  __type(value, __u32);
} xdp_stats_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32); 
  __type(value, u64);
} nat_map SEC(".maps");

static __always_inline unsigned short is_icmp_ping_request(void *data, void *data_end) {
  struct ethhdr *eth = data;
  if (data + sizeof(struct ethhdr) > data_end)
      return 0;

  if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
      return 0;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
      return 0;

  if (iph->protocol != 0x01)
      return 0;

  struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
  if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end)
      return 0;

  return (icmp->type == 8);
}

static __always_inline void swap_ip_addresses(struct __sk_buff *skb) {
  unsigned char src_ip[4];
  unsigned char dst_ip[4];
  bpf_skb_load_bytes(skb, IP_SRC_OFF, src_ip, 4);
  bpf_skb_load_bytes(skb, IP_DST_OFF, dst_ip, 4);
  bpf_skb_store_bytes(skb, IP_SRC_OFF, dst_ip, 4, 0);
  bpf_skb_store_bytes(skb, IP_DST_OFF, src_ip, 4, 0);
}

static __always_inline void swap_mac_addresses(struct __sk_buff *skb) {
  unsigned char src_mac[6];
  unsigned char dst_mac[6];
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_source), src_mac, 6);
  bpf_skb_load_bytes(skb, offsetof(struct ethhdr, h_dest), dst_mac, 6);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_source), dst_mac, 6, 0);
  bpf_skb_store_bytes(skb, offsetof(struct ethhdr, h_dest), src_mac, 6, 0);
}

static __always_inline void update_icmp_type(struct __sk_buff *skb, unsigned char old_type, unsigned char new_type) {
  bpf_l4_csum_replace(skb, ICMP_CSUM_OFF, old_type, new_type, 2);
  bpf_skb_store_bytes(skb, ICMP_TYPE_OFF, &new_type, sizeof(new_type), 0);
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,void *data_end,struct iphdr **iphdr){
	struct iphdr *iph = nh->pos;
	int hdrsize;

	if (iph + 1 > data_end)
		return -1;

	hdrsize = iph->ihl * 4;
	if(hdrsize < sizeof(*iph))
		return -1;

	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = iph;

	return iph->protocol;
}


// not work commnet this 
// SEC("kprobe/ip_queue_get")
// int xlate(struct sk_buff *skb) {
//   struct iphdr *iph = skb->data;
//   struct tcphdr *tcph = (struct tcphdr *)(skb->data + sizeof(struct iphdr));
//   u32 client_ip = iph->saddr;
//   u16 client_port = tcph->source;

//   if (client_ip != CLIENT_IP) {
//     return 0; 
//   }
//   u64 client_key = combine_ip_port(client_ip, client_port);
//   u64 *translated = bpf_map_lookup_elem(&nat_map, &client_key);
//   if (translated == NULL) {
//     return XDP_DROP;
//   }

//   u64 translated_info = *translated;
//   iph->saddr = (translated_info >> 32) & 0xffffffff;
//   tcph->source = translated_info & 0xffff;

//   return 0;
// }

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx)
{
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct hdr_cursor nh;
  struct iphdr *iph;
  int ip_protocol;

  nh.pos = data;
  ip_protocol = parse_iphdr(&nh, data_end, &iph);
  if (ip_protocol < 0)
    return XDP_PASS;

  if (is_icmp_ping_request(data, data_end)) {
    update_icmp_type(ctx, 8, 0);
  }

  u32 client_ip = iph->saddr;
  u32 *backend_ip = bpf_map_lookup_elem(&nat_map, &client_ip);
  if (!backend_ip) {
    return XDP_DROP;
  }

  u32 backend_count = 2; 
  u32 selected_backend_index = client_ip % backend_count; 
  u32 selected_backend_ip = *backend_ip + selected_backend_index;

  iph->daddr = selected_backend_ip;

  return XDP_TX;
}

char _license[] SEC("license") = "GPL";