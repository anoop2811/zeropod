//go:build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct liveness_key);
} liveness_key_map SEC(".maps");


struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, __be16);   // sport
    __type(value, __be16); // dport
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_redirects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 128);
    __type(key, __be16);   // sport
    __type(value, __be16); // dport
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} egress_redirects SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512);
    __type(key, __be16); // proxy port
    __type(value, u8); // unused
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} disable_redirect SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 512); // TBD but should probably be enough
    __type(key, __be16); // remote_port
    __type(value, u8); // unused
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} active_connections SEC(".maps");

struct liveness_key {
    __u32 netns;   // Unique network namespace cookie
    __u32 daddr;   // Destination IPv4 address (from IP header)
    __u16 dport;   // Destination port (from TCP header, in network byte order)
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct liveness_key);
    __type(value, char[512]);  // Cached HTTP response (e.g., "HTTP/1.1 200 OK ...")
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} liveness_cache SEC(".maps");


static __always_inline int is_liveness_probe(struct __sk_buff *skb, struct liveness_key *key_out) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
         return 0;
    if (iph->protocol != IPPROTO_TCP)
         return 0;

    struct tcphdr *tcph = data + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
         return 0;

    void *http = data + (iph->ihl * 4) + (tcph->doff * 4);
    if (http >= data_end)
         return 0;

    char probe[] = "GET /healthz";
    int probe_len = sizeof(probe) - 1;
    if (http + probe_len > data_end)
         return 0;

    int i;
    #pragma unroll
    for (i = 0; i < probe_len; i++) {
         if (((char *)http)[i] != probe[i])
              return 0;
    }

    key_out->netns = bpf_get_netns_cookie(skb);
    key_out->daddr = iph->daddr;
    key_out->dport = tcph->dest;
    return 1;
}

static __always_inline int is_liveness_probe_response(struct __sk_buff *skb, struct liveness_key *key_out) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *iph = data;
    if ((void *)(iph + 1) > data_end)
         return 0;
    if (iph->protocol != IPPROTO_TCP)
         return 0;

    struct tcphdr *tcph = data + (iph->ihl * 4);
    if ((void *)(tcph + 1) > data_end)
         return 0;

    void *http = data + (iph->ihl * 4) + (tcph->doff * 4);
    if (http >= data_end)
         return 0;

    char response[] = "HTTP/1.1 200 OK";
    int response_len = sizeof(response) - 1;
    if (http + response_len > data_end)
         return 0;

    int i;
    #pragma unroll
    for (i = 0; i < response_len; i++) {
         if (((char *)http)[i] != response[i])
              return 0;
    }

    key_out->netns = bpf_get_netns_cookie(skb);
    key_out->daddr = iph->saddr; // src addr becomes dest addr on ingress
    key_out->dport = tcph->source; // src port becomes dest port on ingress
    return 1;
}

static __always_inline void cache_probe_response(struct __sk_buff *skb, struct liveness_key *key) {
    char response[512];
    if (bpf_skb_load_bytes(skb, 0, response, sizeof(response)) < 0)
         return;

    bpf_map_update_elem(&liveness_cache, key, response, BPF_ANY);
}

static __always_inline int send_cached_response(struct __sk_buff *skb, char *cached_response) {
    if (!cached_response)
         return TC_ACT_SHOT;

    int resp_len = 512;
    if (bpf_skb_store_bytes(skb, 0, cached_response, resp_len, 0) < 0)
         return TC_ACT_SHOT;

    return TC_ACT_OK;
}
static __always_inline int disabled(__be16 sport_h, __be16 dport_h) {
    void *disable_redirect_map = &disable_redirect;

    void *disabled_s = bpf_map_lookup_elem(disable_redirect_map, &sport_h);

    if (disabled_s) {
        return 1;
    }

    void *disabled_d = bpf_map_lookup_elem(disable_redirect_map, &dport_h);

    if (disabled_d) {
        return 1;
    }

    return 0;
};

static __always_inline int ingress_redirect(struct __sk_buff *skb, struct tcphdr *tcp) {
    __be16 sport_h = bpf_ntohs(tcp->source);
    __be16 dport_h = bpf_ntohs(tcp->dest);

    struct liveness_key key = {0};
  
    // Check if the incoming packet is a liveness probe
    if (is_liveness_probe(skb, &key)) {
        char *cached_response = bpf_map_lookup_elem(&liveness_cache, &key);
        if (cached_response) {
              return send_cached_response(skb, cached_response);
        }
        // If no cached response, let it pass so we can store it on egress.
    }

    void *active_connections_map = &active_connections;

    void *redirect_map = &ingress_redirects;
    __be16 *new_dest = bpf_map_lookup_elem(redirect_map, &dport_h);

    if (new_dest) {
        // check ports which should not be redirected
        if (disabled(sport_h, dport_h)) {
            // if we can find an acive connection on the source port, we need
            // to redirect regardless until the connection is closed.
            void *conn_sport = bpf_map_lookup_elem(active_connections_map, &sport_h);
            if (!conn_sport) {
                // bpf_printk("ingress: sport %d or dport %d is disabled for redirecting", sport_h, dport_h);
                return TC_ACT_OK;
            }
            // bpf_printk("ingress: port %d found in active connections, redirecting", sport_h);
        }
        // bpf_printk("ingress: changing destination port from %d to %d for packet from %d", dport_h, *new_dest, sport_h);
        tcp->dest = bpf_htons(*new_dest);
    }

    return TC_ACT_OK;
}

static __always_inline int egress_redirect(struct __sk_buff *skb, struct tcphdr *tcp) {
    __be16 sport_h = bpf_ntohs(tcp->source);
    // __be16 dport_h = bpf_ntohs(tcp->dest);

    void *redirect_map = &egress_redirects;
    __be16 *new_source = bpf_map_lookup_elem(redirect_map, &sport_h);

    if (new_source) {
        // bpf_printk("egress: changing source port from %d to %d for packet to %d", sport_h, *new_source, dport_h);
        tcp->source = bpf_htons(*new_source);
    }

    return TC_ACT_OK;
}

static __always_inline int parse_and_redirect(struct __sk_buff *ctx, bool ingress) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void*)eth + sizeof(*eth) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);

        if ((void*)ip + sizeof(*ip) <= data_end) {
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (void*)ip + sizeof(*ip);
                if ((void*)tcp + sizeof(*tcp) <= data_end) {
                    if (ingress) {
                        return ingress_redirect(ctx, tcp);
                    }

                    return egress_redirect(ctx, tcp);
                }
            }
        }
    }

    return 0;
}



SEC("tc")
int tc_redirect_ingress(struct __sk_buff *skb) {
    return parse_and_redirect(skb, true);
}

SEC("tc")
int tc_redirect_egress(struct __sk_buff *skb) {
   
    struct liveness_key *key;
    __u32 zero = 0;
    key = bpf_map_lookup_elem(&liveness_key_map, &zero);
    if (!key) {
        return TC_ACT_OK;  // Avoid stack overflows
    }

    // Check if the packet is a liveness probe response (HTTP 200 OK)
    if (is_liveness_probe_response(skb, &key)) {
         cache_probe_response(skb, &key);
    }

    return parse_and_redirect(skb, false);
}
