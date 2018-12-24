/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

int xdp_open(const char *ifname);
int xdp_can_receive(int sock_fd);
int xdp_can_transfer(int sock_fd);
uint16_t xdp_receive(int sock_fd, uint8_t *buffer, uint16_t max_size);
int xdp_transfer(int sock_fd, uint8_t *buffer, uint16_t len);
