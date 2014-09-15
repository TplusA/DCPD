#ifndef DCPREGS_DRCP_H
#define DCPREGS_DRCP_H

#include <stdint.h>
#include <unistd.h>

int dcpregs_write_drcp_command(const uint8_t *data, size_t length);

#endif /* !DCPREGS_DRCP_H */
