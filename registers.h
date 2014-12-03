#ifndef REGISTERS_H
#define REGISTERS_H

/*!
 * \addtogroup registers SPI registers definitions
 *
 * How to read from and write to SPI registers.
 */
/*!@{*/

#define DCP_REGISTER_FLAG_IS_NOT_CACHEABLE   ((uint8_t)(1 << 0))

/*!
 * Register description and handlers.
 */
struct dcp_register_t
{
    uint8_t address;         /*!< Register number. */
    uint8_t flags;           /*!< See DCP_REGISTER_FLAG_ defines. */
    uint16_t max_data_size;  /*!< Maximum size for variable size, 0 if fixed. */

    /*!
     * How to handle incoming read requests.
     */
    ssize_t (*read_handler)(uint8_t *response, size_t length);

    /*!
     * How to handle incoming write requests.
     */
    int (*write_handler)(const uint8_t *data, size_t length);
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Find register structure by register number (address).
 */
const struct dcp_register_t *register_lookup(uint8_t register_number);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !REGISTERS_H */
