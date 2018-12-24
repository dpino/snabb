/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

#include <stdio.h>
#include <stdint.h>

#include "xdpsock.h"

int xdp_open(const char *ifname)
{
    printf("xdp_open: %s\n", ifname);
    return 0;
}

int xdp_can_receive(int sock_fd)
{
    printf("xdp_can_receive\n");
    return 0;
}

int xdp_can_transfer(int sock_fd)
{
    printf("xdp_can_transfer\n");
    return 0;
}

uint16_t xdp_receive(int sock_fd, uint8_t *buffer, uint16_t max_size)
{
    printf("xdp_receive\n");
    return 0;
}

int xdp_transfer(int sock_fd, uint8_t *buffer, uint16_t len)
{
    printf("xdp_transfer\n");
    return 0;
}
