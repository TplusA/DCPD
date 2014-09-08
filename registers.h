#ifndef REGISTERS_H
#define REGISTERS_H

#define DCP_REGISTER_FLAG_IS_VARIABLE_LENGTH ((uint8_t)(1 << 0))
#define DCP_REGISTER_FLAG_IS_CACHEABLE       ((uint8_t)(1 << 1))

struct register_t
{
    uint8_t address;         /*!< Register number. */
    uint8_t flags;           /*!< See DCP_REGISTER_FLAG_ defines. */
    uint16_t max_data_size;  /*!< Maximum size for variable size, 0 if fixed. */

    /*!
     * How to handle incoming requests.
     */
    ssize_t (*request_handler)(uint8_t *response, size_t length);

    /*!
     * How to process incoming responses.
     */
    int (*response_handler)(void);
};

#endif /* !REGISTERS_H */
