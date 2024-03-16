int xdp_redirect_ingr(struct xdp_md *ctx)
{
   void* data_end = (void*)(long)ctx->data_end;
   void* data = (void*)(long)ctx->data;
   struct ethhdr *eth = data;
   int *ptr1; 
   int tkey = 0;
   int zero = 0;
   uint64_t nh_off;
   long *value; 
   nh_off = sizeof(*eth);
   if (data + nh_off  > data_end)
        return XDP_DROP;
   struct iphdr *ip = data + sizeof(struct ethhdr);
   if ((void *)(ip + 1) > data_end) {
       return XDP_DROP; 
       }
   uint16_t layer3_t = ip->protocol;
   __u32 ip_src = ip->saddr; 

   if (eth->h_proto == htons(ETH_P_ARP)) {
        // ARP always goes through interface with index 1   
        struct arphdr *arp = data + sizeof(struct ethhdr);
        if ((void *)(arp + 1) > data_end)
             return XDP_DROP;
        else 
           return packetforwarder(ctx, nh_off, 1);
	   
   } 
  
   if (layer3_t == IPPROTO_ICMP) {
        // allows ICMP - echo request type only 
        struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
             if ((void *)(icmp + 1) > data_end)
                 return XDP_DROP;
             else {
               if (icmp->type == ICMP_ECHO) {
                 int *ipval = teip_map.lookup(&ip_src);
                 if (ipval != NULL) {
                    return packetforwarder(ctx, nh_off, *ipval);
                    }
                    else {
                       ptr1 = rr_count.lookup(&zero);
                       if (ptr1){
                          *ptr1 += 1;
                          tkey = *ptr1;
                          if (tkey > TEIP_N) {
                          tkey = 1; 
                          rr_count.update(&zero, &tkey);
                          }
                          teip_map.insert(&ip_src, &tkey);
                          return packetforwarder(ctx, nh_off, &tkey);
                       }
                    }
               }
             }
   }        

   if (layer3_t == IPPROTO_ESP) {
       // allows ESP packets - no need to check for new IPs  
       struct ip_esp_hdr *esp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
             if ((void *)(esp + 1) > data_end)
                 return XDP_DROP;
             else {
                 int *ipval = teip_map.lookup(&ip_src);
                 if (ipval != NULL) {
                     return packetforwarder(ctx, nh_off, *ipval);
                 }
             }
    }

   struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
   if ((layer3_t == IPPROTO_UDP) && ((ntohs(udp->dest) == 500) )) { 
       // allows UDP:500 ISAKMP port 
             if ((void *)(udp + 1) > data_end)
                 return XDP_DROP;
             else {
                int *ipval = teip_map.lookup(&ip_src);
                if (ipval != NULL) {
                    return packetforwarder(ctx, nh_off, *ipval);
                } 
                else {
                   ptr1 = rr_count.lookup(&zero);
                   if (ptr1){
                       *ptr1 += 1;
                        tkey = *ptr1;
                        if (tkey > TEIP_N) {
                        tkey = 1; 
                        rr_count.update(&zero, &tkey);
                        }
                        teip_map.insert(&ip_src, &tkey);
                        return packetforwarder(ctx, nh_off, &tkey);
                   }
                }
              } 
     }      


   // EVENTUALLY DROP ANYTHING ELSE other than ICMP-echo|UDP:500|ESP
   return XDP_DROP; 
}

int xdp_redirect_egr(struct xdp_md *ctx)
{
   // on the way back to tunnel initatior...
   void* data_end = (void*)(long)ctx->data_end;
   void* data = (void*)(long)ctx->data;
   struct ethhdr *eth = data;
   uint32_t key = 0;
   uint64_t nh_off;

   nh_off = sizeof(*eth);
   if (data + nh_off  > data_end)
        return XDP_DROP;
   struct iphdr *ip = data + sizeof(struct ethhdr);
   if ((void *)(ip + 1) > data_end) {
       return XDP_DROP; }

   return intfmap.redirect_map(0, 0);

}