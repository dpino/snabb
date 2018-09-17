/* Use of this source code is governed by the Apache 2.0 license; see COPYING. */

int get_sock(char *iface);
void close_sock(void);
struct data_val* read_sock();
int write_sock(int fd, char *pkt, int l);
