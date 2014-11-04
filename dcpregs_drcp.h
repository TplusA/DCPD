#ifndef DCPREGS_DRCP_H
#define DCPREGS_DRCP_H

#include <stdint.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

void dcpregs_UT_init(void);
void dcpregs_UT_deinit(void);
int dcpregs_write_drcp_command(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

#endif /* !DCPREGS_DRCP_H */
