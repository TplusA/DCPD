#ifndef REGISTERS_H
#define REGISTERS_H

#define DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH ((uint8_t)(1 << 0))
#define DCP_REGISTER_FLAG_IS_NOT_CACHEABLE   ((uint8_t)(1 << 1))

/*!
 * Register description and handlers.
 */
struct register_t
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

/*!
 * Find register structure by register number (address).
 */
const struct register_t *register_lookup(uint8_t register_number);

#endif /* !REGISTERS_H */
