/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

#include <linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 1,
};

SEC("xdp_sock")
int xsks_prog()
{
	return bpf_redirect_map(&xsks_map, 0, 0);
}
