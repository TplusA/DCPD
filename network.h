#ifndef NETWORK_H
#define NETWORK_H

#include <stdbool.h>

struct network_socket_pair
{
    int server_fd;
    int peer_fd;
};

#ifdef __cplusplus
extern "C" {
#endif

int network_create_socket(void);
int network_accept_peer_connection(int server_fd);
bool network_have_data(int peer_fd);
void network_close(int *fd);

#ifdef __cplusplus
}
#endif

#endif /* !NETWORK_H */
