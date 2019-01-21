// Use of this source code is governed by the Apache 2.0 license; see COPYING.

/**
 * Part of this code is based on XXX.
 */

enum benchmark_type {
    BENCH_RXDROP = 0,
    BENCH_TXONLY = 1,
    BENCH_L2FWD = 2,
};

struct xdp_umem_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    uint64_t *ring;
    void *map;
};

struct xdp_umem {
    char *frames;
    struct xdp_umem_uqueue fq;
    struct xdp_umem_uqueue cq;
    int fd;
};

struct xdp_uqueue {
    uint32_t cached_prod;
    uint32_t cached_cons;
    uint32_t mask;
    uint32_t size;
    uint32_t *producer;
    uint32_t *consumer;
    struct xdp_desc *ring;
    void *map;
};

struct xdpsock {
    struct xdp_uqueue rx;
    struct xdp_uqueue tx;
    int sfd;
    struct xdp_umem *umem;
    uint32_t outstanding_tx;
    unsigned long rx_npkts;
    unsigned long tx_npkts;
    unsigned long prev_rx_npkts;
    unsigned long prev_tx_npkts;
};

struct options {
    int bench;
    char opt_if[256];
    int ifindex;
    int poll;
    int queue;
    int xdp_bind_flags;
    int xdp_flags;
};

typedef struct options options_t;

typedef struct xdp_context {
   struct xdpsock *xsks[1];
   int num_socks;
   struct pollfd fds_in[1];
   struct pollfd fds_out[1];
} xdp_context_t;

bool can_receive(xdp_context_t* ctx);
bool can_transfer(xdp_context_t *ctx);
int receive(xdp_context_t* ctx, char* pkt);
int transfer(xdp_context_t *ctx, const char* data, size_t length);
xdp_context_t* init_xdp(const char *ifname);
