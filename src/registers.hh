/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef REGISTERS_HH
#define REGISTERS_HH

#include <string>
#include <stdexcept>

#include "dynamic_buffer.h"

/*!
 * \addtogroup registers SPI registers definitions
 *
 * How to read from and write to SPI registers.
 */
/*!@{*/

namespace Regs
{

struct ProtocolLevel { uint32_t code; };

constexpr static inline uint32_t mk_version(uint8_t major, uint8_t minor, uint8_t micro)
{
    return 0;
}

#define REGISTER_MK_VERSION(MAJOR, MINOR, MICRO) \
    ((uint32_t((MAJOR) & 0xff) << 16) | \
     (uint32_t((MINOR) & 0xff) <<  8) | \
     (uint32_t((MICRO) & 0xff) <<  0))

class no_handler: public std::runtime_error
{
  public:
    explicit no_handler(const char *s):
        std::runtime_error::runtime_error(s)
    {}
};

class io_error: public std::runtime_error
{
  private:
    const ssize_t io_result_;

  public:
    explicit io_error(const char *s, ssize_t io_result):
        std::runtime_error::runtime_error(s),
        io_result_(io_result)
    {}

    ssize_t result() const { return io_result_; }
};

/*!
 * Register description and handlers.
 */
class Register
{
  public:
    const uint8_t address_;         /*!< Register number. */
    const std::string name_;
    const ProtocolLevel minimum_protocol_version_;
    const ProtocolLevel maximum_protocol_version_;

    const uint16_t max_data_size_;  /*!< Maximum size for variable size. */

  private:
    /*!
     * How to handle incoming read requests (registers with static size).
     */
    ssize_t (*read_handler_)(uint8_t *response, size_t length);

    /*!
     * How to handle incoming read requests (registers with dynamic size).
     */
    bool (*read_handler_dynamic_)(struct dynamic_buffer *buffer);

    /*!
     * How to handle incoming write requests.
     */
    int (*write_handler_)(const uint8_t *data, size_t length);

  public:
    Register(const Register &) = delete;
    Register &operator=(const Register &) = delete;

    Register(Register &&) = default;

    Register(std::string &&name, uint8_t address,
             uint32_t minimum_protocol_version,
             uint32_t maximum_protocol_version, uint16_t max_data_size,
             ssize_t (*read_handler)(uint8_t *, size_t),
             int (*write_handler)(const uint8_t *, size_t)):
        address_(address),
        name_(std::move(name)),
        minimum_protocol_version_{minimum_protocol_version},
        maximum_protocol_version_{maximum_protocol_version},
        max_data_size_(max_data_size),
        read_handler_(read_handler),
        read_handler_dynamic_(nullptr),
        write_handler_(write_handler)
    {}

    Register(std::string &&name, uint8_t address,
             uint32_t minimum_protocol_version,
             uint32_t maximum_protocol_version,
             bool (*read_handler_dynamic)(struct dynamic_buffer *),
             int (*write_handler)(const uint8_t *, size_t)):
        address_(address),
        name_(std::move(name)),
        minimum_protocol_version_{minimum_protocol_version},
        maximum_protocol_version_{maximum_protocol_version},
        max_data_size_(0),
        read_handler_(nullptr),
        read_handler_dynamic_(read_handler_dynamic),
        write_handler_(write_handler)
    {}

    Register(std::string &&name, uint8_t address,
             uint32_t minimum_protocol_version, uint16_t max_data_size,
             ssize_t (*read_handler)(uint8_t *, size_t) = nullptr,
             int (*write_handler)(const uint8_t *, size_t) = nullptr):
        Register(std::move(name), address, minimum_protocol_version,
                 REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                 max_data_size, read_handler, write_handler)
    {}

    Register(std::string &&name, uint8_t address,
             uint32_t minimum_protocol_version, uint16_t max_data_size,
             int (*write_handler)(const uint8_t *, size_t)):
        Register(std::move(name), address, minimum_protocol_version,
                 REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                 max_data_size, nullptr, write_handler)
    {}

    Register(std::string &&name, uint8_t address,
             uint32_t minimum_protocol_version,
             bool (*read_handler_dynamic)(struct dynamic_buffer *),
             int (*write_handler)(const uint8_t *, size_t) = nullptr):
        Register(std::move(name), address, minimum_protocol_version,
                 REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX),
                 read_handler_dynamic, write_handler)
    {}


    /*!
     * Whether or not the register has static size.
     *
     * In case of static size, the #Regs::Register::read_handler_ function
     * must be called with a preallocated buffer large enough to store at least
     * #Regs::Register::max_data_size_ bytes to read out the register.
     * Otherwise, in case of dynamic size, the
     * #Regs::Register::read_handler_dynamic_ function must be called with an
     * empty #dynamic_buffer.
     */
    bool is_static_size() const { return max_data_size_ > 0; }

    size_t read(uint8_t *response, size_t length) const
    {
        if(read_handler_ == nullptr)
            throw no_handler("read");

        const auto result = read_handler_(response, length);

        if(result < 0)
            throw io_error("read", result);

        return result;
    }

    void read(dynamic_buffer &buffer) const
    {
        if(read_handler_dynamic_ == nullptr)
            throw no_handler("read dynamic");

        if(!read_handler_dynamic_(&buffer))
            throw io_error("read dynamic", -1);
    }

    void write(const uint8_t *data, size_t length) const
    {
        if(write_handler_ == nullptr)
            throw no_handler("write");

        const auto result = write_handler_(data, length);

        if(result < 0)
            throw io_error("write", result);
    }

    /*!\internal
     * For unit tests.
     */
    bool has_handler(ssize_t (*handler)(uint8_t *, size_t)) const
    {
        return read_handler_ == handler;
    }

    /*!\internal
     * For unit tests.
     */
    bool has_handler(bool (*handler)(struct dynamic_buffer *)) const
    {
        return read_handler_dynamic_ == handler;
    }

    /*!\internal
     * For unit tests.
     */
    bool has_handler(int (*handler)(const uint8_t *, size_t)) const
    {
        return write_handler_ == handler;
    }
};

/*!
 * Evil global variable: For unit tests, must not be used in production code.
 *
 * While this pointer contains a non-NULL value, it is possible to look up
 * register 0 using #Regs::lookup(). The function will then return this
 * pointer. This is only useful for unit tests, e.g., to inject specific read
 * or write handlers.
 *
 * Special care must be taken when using this pointer in unit tests.
 * - In any test suite that sets this pointer, it is mandatory to reset this
 *   pointer back to \c nullptr in the test harness setup. The #Regs::init()
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
extern const Register *register_zero_for_unit_tests;

/*!
 * Initialize register handling code.
 *
 * \note
 *     This function also calls the \c dcpregs_*_init() functions.
 */
void init(void (*register_changed_callback)(uint8_t reg_number));

/*!
 * Free resources.
 *
 * \note
 *     This function also calls the \c dcpregs_*_deinit() functions.
 */
void deinit(void);

/*!
 * Set explicit protocol version.
 *
 * Default is the maximum supported version.
 */
bool set_protocol_level(uint8_t major, uint8_t minor, uint8_t micro);

/*!
 * Get the currently configured protocol version.
 */
const ProtocolLevel get_protocol_level(void);

/*!
 * Get all ranges of supported protocol levels.
 */
size_t get_supported_protocol_levels(const ProtocolLevel **level_ranges);

/*!
 * Extract version components from version code.
 */
void unpack_protocol_level(/* cppcheck-suppress passedByValue */
                           const ProtocolLevel level,
                           uint8_t *major, uint8_t *minor,
                           uint8_t *micro);

/*!
 * Find register structure by register number (address).
 */
const Register *lookup(uint8_t register_number);

}

/*!@}*/

#endif /* !REGISTERS_HH */
