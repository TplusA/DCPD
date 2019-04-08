/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef FIXPOINT_HH
#define FIXPOINT_HH

#include <iostream>
#include <limits>
#include <cmath>
#include <cstdint>
#include <cstdlib>

/*!
 * Compact representation of small real numbers.
 *
 * This class defines a 14-bit fix point format and implements conversion
 * functions from and to native types.
 *
 * The format uses 10 bits for the pre-decimal point position, composed of an
 * explicit sign bit as most significant bit, and 9 bits for an unsigned value
 * representing the magnitude. Thus, the value range is -511...511, and there
 * are two representations for 0 in the pre-decimal position (+0 and -0). This
 * property is required for representing numbers such as -0.25.
 *
 * There are 4 bits for the decimal place. These bits store an unsigned integer
 * which is to be interpreted as nominator x in the expression x/16. Thus, real
 * numbers can be represented with a precision of 0.0625.
 *
 * The representation for NaN is -0, i.e., pre-decimal and decimal magnitudes
 * are 0, and the sign bit is set. Such a number makes no sense, so we are
 * using it to represent NaN.
 *
 * There is no representation for infinity. The #FixPoint class is not aware of
 * the infinities and does not handle such values.
 *
 * Conversion functions defined by this class take care of correct rounding and
 * avoiding oscillation when converting values back and forth between fix point
 * and double representations.
 */
class FixPoint
{
  private:
    static constexpr const unsigned int PREDECIMAL_BITS = 10;
    static constexpr const unsigned int DECIMAL_BITS = 4;
    static constexpr const uint16_t SIGN_BIT_MASK = 1U << (PREDECIMAL_BITS - 1);

  public:
    static constexpr const uint8_t MAX_DECIMAL_VALUE = (1U << DECIMAL_BITS) - 1U;
    static constexpr const double PRECISION = 1.0 / double(1U << DECIMAL_BITS);

    static constexpr const int16_t MAX_AS_INT16 = (1U << (PREDECIMAL_BITS - 1)) - 1U;
    static constexpr const int16_t MIN_AS_INT16 = -uint16_t(MAX_AS_INT16);

    static constexpr const double MAX_AS_DOUBLE =
        double(MAX_AS_INT16) + double(MAX_DECIMAL_VALUE) * PRECISION;

    static constexpr const double MIN_AS_DOUBLE = -MAX_AS_DOUBLE;

  private:
    bool is_nan_;
    uint16_t pre_decimal_;
    uint8_t decimal_;
    bool round_towards_zero_;

  public:
    FixPoint(const FixPoint &) = default;
    FixPoint(FixPoint &&) = default;
    FixPoint &operator=(const FixPoint &) = default;
    FixPoint &operator=(FixPoint &&) = default;

    constexpr explicit FixPoint(int16_t input) throw():
        is_nan_(input < MIN_AS_INT16 || input > MAX_AS_INT16),
        pre_decimal_(input < MIN_AS_INT16 || input > MAX_AS_INT16
                     ? 0
                     : encode_pre_decimal(input, std::signbit(input))),
        decimal_(0),
        round_towards_zero_(false)
    {}

    explicit FixPoint(double input) throw()
    {
        if(!std::isnan(input))
        {
            if(input > MIN_AS_DOUBLE - (PRECISION / 2.0) &&
               input < MAX_AS_DOUBLE + (PRECISION / 2.0))
            {
                is_nan_ = false;
                const int16_t input_as_int16 = std::trunc(input);
                pre_decimal_ = encode_pre_decimal(input_as_int16, std::signbit(input));
                const double abs_difference = std::abs(input - input_as_int16);
                decimal_ = std::round(abs_difference / PRECISION);

                if(decimal_ == MAX_DECIMAL_VALUE + 1)
                {
                    decimal_ = 0;
                    ++pre_decimal_;
                }

                round_towards_zero_ = (decimal_ == (MAX_DECIMAL_VALUE + 1) / 2 &&
                                       abs_difference < 0.5);
                return;
            }
        }

        mk_nan();
    }

    explicit FixPoint(const uint8_t *const data, size_t length) throw()
    {
        if(length >= 2)
        {
            pre_decimal_ = (uint16_t(data[0] & 0x3f) << 4) | ((data[1] >> 4) & 0x0f);
            decimal_ = data[1] & 0x0f;

            if(pre_decimal_ != SIGN_BIT_MASK || decimal_ > 0)
            {
                is_nan_ = false;
                round_towards_zero_ = false;
                return;
            }
        }

        mk_nan();
    }

    bool is_nan() const throw() { return is_nan_; }

    double to_double() const throw()
    {
        if(is_nan())
            return std::numeric_limits<double>::quiet_NaN();

        const int16_t pre_decimal = decode_pre_decimal(pre_decimal_);

        return (signbit(pre_decimal_)
                ? double(pre_decimal) - PRECISION * decimal_
                : double(pre_decimal) + PRECISION * decimal_);
    }

    int16_t to_int16() const throw()
    {
        return !is_nan()
            ? (decode_pre_decimal(pre_decimal_) +
               one_for_rounding(signbit(pre_decimal_), round_towards_zero_,
                                decimal_))
            : INT16_MIN;
    }

    bool to_buffer(uint8_t *buffer, size_t length) const throw()
    {
        if(length < 2)
            return false;

        if(!is_nan_)
        {
            buffer[0] = (pre_decimal_ >> 4) & 0x3f;
            buffer[1] = (pre_decimal_ << 4) | decimal_;
        }
        else
        {
            buffer[0] = SIGN_BIT_MASK >> 4;
            buffer[1] = 0;
        }

        return true;
    }

    friend std::ostream &operator<<(std::ostream &os, const FixPoint &fp);

  private:
    void mk_nan()
    {
        is_nan_ = true;
        pre_decimal_ = 0;
        decimal_ = 0;
        round_towards_zero_ = false;
    }

    static inline uint16_t encode_pre_decimal(const int16_t input,
                                              bool is_negative)
    {
        return (is_negative
                ? (uint16_t(-input) | SIGN_BIT_MASK)
                : input);
    }

    static inline int16_t decode_pre_decimal(const uint16_t pre_decimal)
    {
        return signbit(pre_decimal) ? -int16_t(abs(pre_decimal)) : pre_decimal;
    }

    static inline bool signbit(uint16_t pre_decimal)
    {
        return (pre_decimal & SIGN_BIT_MASK) != 0;
    }

    static inline uint16_t abs(uint16_t pre_decimal)
    {
        return pre_decimal & ~SIGN_BIT_MASK;
    }

    static inline int16_t one_for_rounding(bool down, bool towards_zero,
                                           const uint8_t decimal)
    {
        return decimal < (1U << (DECIMAL_BITS - 1)) || towards_zero
            ? 0
            : (down ? -1 : 1);
    }
};

inline std::ostream &operator<<(std::ostream &os, const FixPoint &fp)
{
    /* C++ iostreams suck... */
    char buffer[100];

    if(fp.is_nan_)
        snprintf(buffer, sizeof(buffer),
                 "NaN (0x%04x:%02u)", fp.pre_decimal_, fp.decimal_);
    else
        snprintf(buffer, sizeof(buffer), "%c%u.%.4u [0x%04x:%02u]",
                 FixPoint::signbit(fp.pre_decimal_) ? '-' : '+',
                 FixPoint::abs(fp.pre_decimal_),
                 uint32_t(double(fp.decimal_) * FixPoint::PRECISION * 10000U),
                 fp.pre_decimal_, fp.decimal_);

    os << buffer;

    return os;
}

#endif /* !FIXPOINT_HH */
