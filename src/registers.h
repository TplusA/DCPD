/*
 * Copyright (C) 2015  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * DCPD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * DCPD is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with DCPD.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef REGISTERS_H
#define REGISTERS_H

#include "dynamic_buffer.h"

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
    uint16_t max_data_size;  /*!< Maximum size for variable size. */

    /*!
     * How to handle incoming read requests (registers with static size).
     */
    ssize_t (*read_handler)(uint8_t *response, size_t length);

    /*!
     * How to handle incoming read requests (registers with dynamic size).
     */
    bool (*read_handler_dynamic)(struct dynamic_buffer *buffer);

    /*!
     * How to handle incoming write requests.
     */
    int (*write_handler)(const uint8_t *data, size_t length);
};

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize register handling code.
 *
 * Some registers return static content obtained from the command line or
 * configuration file. These data are passed here.
 *
 * \note
 *     This function also calls the \c dcpregs_*_init() functions.
 */
void register_init(const char *ethernet_mac_address,
                   const char *wlan_mac_address,
                   const char *connman_config_path,
                   void (*register_changed_callback)(uint8_t reg_number));

/*!
 * Free resources.
 *
 * \note
 *     This function also calls the \c dcpregs_*_deinit() functions.
 */
void register_deinit(void);

/*!
 * Find register structure by register number (address).
 */
const struct dcp_register_t *register_lookup(uint8_t register_number);

/*!
 * Whether or not the register has static size.
 *
 * In case of static size, the #dcp_register_t::read_handler() function must be
 * called with a preallocated buffer large enough to store at least
 * #dcp_register_t::max_data_size bytes to read out the register. Otherwise, in
 * case on dynamic size, the #dcp_register_t::read_handler_dynamic() function
 * must be called with an empty #dynamic_buffer.
 */
bool register_is_static_size(const struct dcp_register_t *reg);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !REGISTERS_H */
