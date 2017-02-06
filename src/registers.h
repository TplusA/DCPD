/*
 * Copyright (C) 2015, 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

struct RegisterProtocolLevel { uint32_t code; };

#define REGISTER_MK_VERSION(MAJOR, MINOR, MICRO) \
    ((((MAJOR) & 0xff) << 16) | \
     (((MINOR) & 0xff) <<  8) | \
     (((MICRO) & 0xff) <<  0))

/*!
 * Register description and handlers.
 */
struct dcp_register_t
{
    uint8_t address;         /*!< Register number. */
    struct RegisterProtocolLevel minimum_protocol_version;
    struct RegisterProtocolLevel maximum_protocol_version;

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

/*!
 * Evil global variable: For unit tests, must not be used in production code.
 *
 * While this pointer contains a non-NULL value, it is possible to look up
 * register 0 using #register_lookup(). The function will then return this
 * pointer. This is only useful for unit tests, e.g., to inject specific read
 * or write handlers.
 *
 * Special care must be taken when using this pointer in unit tests.
 * - In any test suite that sets this pointer, it is mandatory to reset this
 *   pointer back to \c NULL in the test harness setup. The #register_init()
 *   function does this as well, so it is not required to set the pointer
 *   directly if that function is called anyway during setup.
 * - Because this is a simple pointer, there is no protection against
 *   concurrent access. If tests are to be run in parallel, the test suite
 *   needs to make sure it will work correctly by locking or excluding specific
 *   tests from parallel execution.
 *
 * \attention
 *     Do not---NEVER EVER---write to this pointer in production.
 *     All hell will break loose.
 */
extern const struct dcp_register_t *register_zero_for_unit_tests;

#ifdef __cplusplus
extern "C" {
#endif

/*!
 * Initialize register handling code.
 *
 * \note
 *     This function also calls the \c dcpregs_*_init() functions.
 */
void register_init(void (*register_changed_callback)(uint8_t reg_number));

/*!
 * Free resources.
 *
 * \note
 *     This function also calls the \c dcpregs_*_deinit() functions.
 */
void register_deinit(void);

/*!
 * Set explicit protocol version.
 *
 * Default is the maximum supported version.
 */
bool register_set_protocol_level(uint8_t major, uint8_t minor, uint8_t micro);

/*!
 * Get the currently configured protocol version.
 */
const struct RegisterProtocolLevel *register_get_protocol_level(void);

/*!
 * Get all ranges of supported protocol levels.
 */
size_t register_get_supported_protocol_levels(const struct RegisterProtocolLevel **level_ranges);

/*!
 * Extract version components from version code.
 */
void register_unpack_protocol_level(/* cppcheck-suppress passedByValue */
                                    const struct RegisterProtocolLevel level,
                                    uint8_t *major, uint8_t *minor,
                                    uint8_t *micro);

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
