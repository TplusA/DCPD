#ifndef DCPREGS_DRCP_H
#define DCPREGS_DRCP_H

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

int dcpregs_write_drcp_command(const uint8_t *data, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_DRCP_H */
