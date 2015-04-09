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
 * Initialize register handling code.
 *
 * Some registers return static content obtained from the command line or
 * configuration file. These data are passed here.
 */
void register_init(const char *ethernet_interface_name,
                   const char *ethernet_mac_address,
                   const char *wlan_interface_name,
                   const char *wlan_mac_address);

/*!
 * Find register structure by register number (address).
 */
const struct dcp_register_t *register_lookup(uint8_t register_number);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !REGISTERS_H */
