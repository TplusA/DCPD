#ifndef DCPDEFS_H
#define DCPDEFS_H

#include <stdint.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#define DCP_HEADER_SIZE        4
#define DCP_HEADER_DATA_OFFSET 2

#define DCP_COMMAND_WRITE_REGISTER       0
#define DCP_COMMAND_READ_REGISTER        1
#define DCP_COMMAND_MULTI_WRITE_REGISTER 2
#define DCP_COMMAND_MULTI_READ_REGISTER  3

static inline uint16_t dcp_read_header_data(const uint8_t *src)
{
    return src[0] | (src[1] << 8);
}

static inline void dcp_put_header_data(uint8_t *dest, uint16_t value)
{
    dest[0] = value & 0xff;
    dest[1] = value >> 8;
}

/*!@}*/

#endif /* !DCPDEFS_H */
