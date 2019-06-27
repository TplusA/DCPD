/*
 * Copyright (C) 2017, 2019  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of DCPD.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA  02110-1301, USA.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>
#include <cmath>
#include <array>
#include <tuple>
#include <random>

#include "fixpoint.hh"

namespace fixpoint_tests
{

static void expect_equal_doubles(double expected, double value)
{
    if(std::isnan(expected) || std::isnan(value))
    {
        if(std::isnan(expected) && std::isnan(value))
            return;

        cut_fail("Expected %.20f, got %.20f", expected, value);
    }

    cut_assert_operator(expected, <=, value,
                        cut_message("Expected %.20f <= %.20f", expected, value));
    cut_assert_operator(expected, >=, value,
                        cut_message("Expected %.20f >= %.20f", expected, value));
}

static void expect_equal_doubles(double expected, double value, double input)
{
    if(std::isnan(expected) || std::isnan(value))
    {
        if(std::isnan(expected) && std::isnan(value))
            return;

        cut_fail("Failed for input %.20f: expected %.20f, got %.20f",
                 input, expected, value);
    }

    cut_assert_operator(expected, <=, value,
                        cut_message("Failed for input %.20f: expected %.20f <= %.20f",
                                    input, expected, value));
    cut_assert_operator(expected, >=, value,
                        cut_message("Failed for input %.20f: expected %.20f <= %.20f",
                                    input, expected, value));
}

static void expect_conversion_result(int16_t expected, const FixPoint &fp)
{
    cut_assert_false(fp.is_nan());
    cppcut_assert_equal(expected, fp.to_int16());
}

static void expect_conversion_result(double expected, const FixPoint &fp)
{
    cut_assert_false(fp.is_nan());

    const double fp_as_double = fp.to_double();
    expect_equal_doubles(expected, fp_as_double);
}

void test_integer_zero()
{
    const auto value = FixPoint(int16_t(0));
    expect_conversion_result(int16_t(0), value);
}

void test_integer_one()
{
    const auto value = FixPoint(int16_t(1));
    expect_conversion_result(int16_t(1), value);
}

void test_integer_minus_one()
{
    const auto value = FixPoint(int16_t(-1));
    expect_conversion_result(int16_t(-1), value);
}

void test_integer_min()
{
    const auto value = FixPoint(FixPoint::MIN_AS_INT16);
    expect_conversion_result(FixPoint::MIN_AS_INT16, value);
}

void test_integer_max()
{
    const auto value = FixPoint(FixPoint::MAX_AS_INT16);
    expect_conversion_result(FixPoint::MAX_AS_INT16, value);
}

void test_integer_overflow_generates_nan()
{
    const auto value = FixPoint(int16_t(FixPoint::MAX_AS_INT16 + 1));
    cut_assert_true(value.is_nan());
    cppcut_assert_equal(int16_t(INT16_MIN), value.to_int16());
    cut_assert_true(std::isnan(value.to_double()));
}

void test_integer_underflow_generates_nan()
{
    const auto value = FixPoint(int16_t(FixPoint::MIN_AS_INT16 - 1));
    cut_assert_true(value.is_nan());
    cppcut_assert_equal(int16_t(INT16_MIN), value.to_int16());
    cut_assert_true(std::isnan(value.to_double()));
}

void test_double_zero()
{
    const auto value = FixPoint(0.0);
    expect_conversion_result(int16_t(0), value);
}

void test_double_one()
{
    const auto value = FixPoint(1.0);
    expect_conversion_result(int16_t(1), value);
}

void test_double_minus_one()
{
    const auto value = FixPoint(-1.0);
    expect_conversion_result(int16_t(-1), value);
}

void test_double_3_75()
{
    const auto value = FixPoint(3.75);
    expect_conversion_result(3.75, value);
}

void test_double_minus_7_25()
{
    const auto value = FixPoint(-7.25);
    expect_conversion_result(-7.25, value);
}

void test_conversion_to_native_types()
{
    const auto pos = FixPoint(10.5);

    expect_equal_doubles(10.5, pos.to_double());
    cppcut_assert_equal(int16_t(11), pos.to_int16());

    const auto neg = FixPoint(-5.0625);

    expect_equal_doubles(-5.0625, neg.to_double());
    cppcut_assert_equal(int16_t(-5), neg.to_int16());
}

void test_serialization_to_buffer_requires_minimum_buffer_size()
{
    const auto value = FixPoint(-0.25);
    const std::array<const uint8_t, 8> expected_empty{0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55};
    const std::array<const uint8_t, 8> expected_filled{0x55, 0x55, 0x20, 0x04, 0x55, 0x55, 0x55, 0x55};

    std::array<uint8_t, 8> buffer;

    std::fill(buffer.begin(), buffer.end(), 0x55);
    cut_assert_false(value.to_buffer(buffer.data() + 2, 0));
    cut_assert_equal_memory(expected_empty.data(), expected_empty.size(),
                            buffer.data(), buffer.size());

    std::fill(buffer.begin(), buffer.end(), 0x55);
    cut_assert_false(value.to_buffer(buffer.data() + 2, 1));
    cut_assert_equal_memory(expected_empty.data(), expected_empty.size(),
                            buffer.data(), buffer.size());

    std::fill(buffer.begin(), buffer.end(), 0x55);
    cut_assert_true(value.to_buffer(buffer.data() + 2, 2));
    cut_assert_equal_memory(expected_filled.data(), expected_filled.size(),
                            buffer.data(), buffer.size());

    std::fill(buffer.begin(), buffer.end(), 0x55);
    cut_assert_true(value.to_buffer(buffer.data() + 2, 3));
    cut_assert_equal_memory(expected_filled.data(), expected_filled.size(),
                            buffer.data(), buffer.size());

    std::fill(buffer.begin(), buffer.end(), 0x55);
    cut_assert_true(value.to_buffer(buffer.data() + 2, 4));
    cut_assert_equal_memory(expected_filled.data(), expected_filled.size(),
                            buffer.data(), buffer.size());
}

static void expect_serialization_result(const std::array<const uint8_t, 2> &expected,
                                        const FixPoint &value)
{
    std::array<uint8_t, 2> buffer;
    cut_assert_true(value.to_buffer(buffer.data(), buffer.size()));
    cut_assert_equal_memory(expected.data(), expected.size(), buffer.data(), buffer.size());
}

void test_serialize_zero_to_buffer()
{
    const auto value = FixPoint(int16_t(0));
    expect_serialization_result({0x00, 0x00}, value);
}

void test_serialize_one_to_buffer()
{
    const auto value = FixPoint(int16_t(1));
    expect_serialization_result({0x00, 0x10}, value);
}

void test_serialize_42_to_buffer()
{
    const auto value = FixPoint(int16_t(42));
    expect_serialization_result({0x02, 0xa0}, value);
}

void test_serialize_intmax_to_buffer()
{
    const auto value = FixPoint(FixPoint::MAX_AS_INT16);
    expect_serialization_result({0x1f, 0xf0}, value);
}

void test_serialize_minus_one_to_buffer()
{
    const auto value = FixPoint(int16_t(-1));
    expect_serialization_result({0x20, 0x10}, value);
}

void test_serialize_minus_123_to_buffer()
{
    const auto value = FixPoint(int16_t(-123));
    expect_serialization_result({0x27, 0xb0}, value);
}

void test_serialize_intmin_to_buffer()
{
    const auto value = FixPoint(FixPoint::MIN_AS_INT16);
    expect_serialization_result({0x3f, 0xf0}, value);
}

void test_serialize_500_125_to_buffer()
{
    const auto value = FixPoint(500.125);
    expect_serialization_result({0x1f, 0x42}, value);
}

void test_serialize_dblmax_to_buffer()
{
    const auto value = FixPoint(FixPoint::MAX_AS_DOUBLE);
    expect_serialization_result({0x1f, 0xff}, value);
}

void test_serialize_minus_88_875_to_buffer()
{
    const auto value = FixPoint(-88.875);
    expect_serialization_result({0x25, 0x8e}, value);
}

void test_serialize_dblmin_to_buffer()
{
    const auto value = FixPoint(FixPoint::MIN_AS_DOUBLE);
    expect_serialization_result({0x3f, 0xff}, value);
}

void test_serialize_nan_to_buffer()
{
    const auto value = FixPoint(std::numeric_limits<double>::quiet_NaN());
    cut_assert_true(value.is_nan());
    expect_serialization_result({0x20, 0x00}, value);
}

void test_deserialization_from_buffer_requires_minimum_buffer_size()
{
    const std::array<const uint8_t, 4> input{0x17, 0xfc, 0x00, 0x00};

    auto value = FixPoint(input.data(), 0);
    cut_assert_true(value.is_nan());

    value = FixPoint(input.data(), 1);
    cut_assert_true(value.is_nan());

    value = FixPoint(input.data(), 2);
    cut_assert_false(value.is_nan());
    expect_equal_doubles(383.75, value.to_double());

    value = FixPoint(input.data(), 3);
    cut_assert_false(value.is_nan());
    expect_equal_doubles(383.75, value.to_double());

    value = FixPoint(input.data(), 4);
    cut_assert_false(value.is_nan());
    expect_equal_doubles(383.75, value.to_double());
}

static void expect_deserialization_result(double expected,
                                          const std::array<const uint8_t, 2> &data)
{
    const auto value = FixPoint(data.data(), data.size());
    expect_equal_doubles(expected, value.to_double());
}

void test_deserialize_zero_from_buffer()
{
    expect_deserialization_result(0.0, {0x00, 0x00});
}

void test_deserialize_0_5_from_buffer()
{
    expect_deserialization_result(0.5, {0x00, 0x08});
}

void test_deserialize_1_5_from_buffer()
{
    expect_deserialization_result(1.5, {0x00, 0x18});
}

void test_deserialize_491_8125_from_buffer()
{
    expect_deserialization_result(491.8125, {0x1e, 0xbd});
}

void test_deserialize_minus_0_5_from_buffer()
{
    expect_deserialization_result(-0.5, {0x20, 0x08});
}

void test_deserialize_minus_1_5_from_buffer()
{
    expect_deserialization_result(-1.5, {0x20, 0x18});
}

void test_deserialize_minus_367_3125_from_buffer()
{
    expect_deserialization_result(-367.3125, {0x36, 0xf5});
}

void test_deserialize_nan_from_buffer()
{
    expect_deserialization_result(std::numeric_limits<double>::quiet_NaN(), {0x20, 0x00});
}

void test_deserialize_dblmax_from_buffer()
{
    expect_deserialization_result(FixPoint::MAX_AS_DOUBLE, {0x1f, 0xff});
}

void test_deserialize_dblmin_from_buffer()
{
    expect_deserialization_result(FixPoint::MIN_AS_DOUBLE, {0x3f, 0xff});
}

void test_deserialization_considers_14_bits_only()
{
    expect_deserialization_result( 0.0,  {0x80, 0x00});
    expect_deserialization_result( 0.0,  {0x40, 0x00});
    expect_deserialization_result( 0.0,  {0xc0, 0x00});
    expect_deserialization_result(-1.0,  {0xa0, 0x10});
    expect_deserialization_result( 5.5,  {0x40, 0x58});
    expect_deserialization_result(-8.25, {0xe0, 0x84});
    expect_deserialization_result(-0.75, {0xe0, 0x0c});
}

void test_rounding_during_conversion_to_native_types()
{
    static const std::array<const std::tuple<const double, const int, const double>, 24> expectations
    {
        /* some simple cases */
        std::make_tuple( 5.4   ,  5,  5.375),
        std::make_tuple( 5.4999,  5,  5.5),
        std::make_tuple( 5.5   ,  6,  5.5),
        std::make_tuple( 5.5001,  6,  5.5),
        std::make_tuple( 5.6   ,  6,  5.625),
        std::make_tuple( 5.9999,  6,  6.0),
        std::make_tuple( 6.0001,  6,  6.0),
        std::make_tuple(-5.4   , -5, -5.375),
        std::make_tuple(-5.4999, -5, -5.5),
        std::make_tuple(-5.5   , -6, -5.5),
        std::make_tuple(-5.5001, -6, -5.5),
        std::make_tuple(-5.6   , -6, -5.625),
        std::make_tuple(-5.9999, -6, -6.0),
        std::make_tuple(-6.0001, -6, -6.0),
        std::make_tuple(double(FixPoint::MAX_AS_INT16) + 0.75,
                        FixPoint::MAX_AS_INT16 + 1,
                        double(FixPoint::MAX_AS_INT16) + 0.75),
        std::make_tuple(double(FixPoint::MIN_AS_INT16) - 0.75,
                        FixPoint::MIN_AS_INT16 - 1,
                        double(FixPoint::MIN_AS_INT16) - 0.75),

        /* cases found by randomized unit test */
        std::make_tuple(FixPoint::MIN_AS_DOUBLE - FixPoint::PRECISION / 2.0,
                        INT16_MIN,
                        std::numeric_limits<double>::quiet_NaN()),
        std::make_tuple(std::nextafter(FixPoint::MIN_AS_DOUBLE - FixPoint::PRECISION / 2.0, 0.0),
                        FixPoint::MIN_AS_INT16 - 1,
                        double(FixPoint::MIN_AS_DOUBLE)),
        std::make_tuple(FixPoint::MAX_AS_DOUBLE + FixPoint::PRECISION / 2.0,
                        INT16_MIN,
                        std::numeric_limits<double>::quiet_NaN()),
        std::make_tuple(std::nextafter(FixPoint::MAX_AS_DOUBLE + FixPoint::PRECISION / 2.0, 0.0),
                        FixPoint::MAX_AS_INT16 + 1,
                        double(FixPoint::MAX_AS_DOUBLE)),
        std::make_tuple( 3.4753,    3,  3.5),
        std::make_tuple(-3.4753,   -3, -3.5),
        std::make_tuple( 0.817499,  1,  0.8125),
        std::make_tuple(-0.817499, -1, -0.8125),
    };

    for(const auto &p : expectations)
    {
        const auto value = FixPoint(std::get<0>(p));
        const auto int_result = value.to_int16();
        const auto dbl_result = value.to_double();

        cppcut_assert_equal(std::get<1>(p), int(int_result),
                            cut_message("Failed for input %.20f", std::get<0>(p)));
        expect_equal_doubles(std::get<2>(p), dbl_result, std::get<0>(p));
    }
}

static int16_t compute_expected_int16(const double dbl)
{
    return ((dbl < FixPoint::MIN_AS_DOUBLE - (FixPoint::PRECISION / 2.0)) ||
            (dbl > FixPoint::MAX_AS_DOUBLE + (FixPoint::PRECISION / 2.0)))
        ? INT16_MIN
        : int16_t(std::round(dbl));
}

static double compute_expected_double(const double dbl)
{
    if((dbl <= FixPoint::MIN_AS_DOUBLE - (FixPoint::PRECISION / 2.0)) ||
       (dbl >= FixPoint::MAX_AS_DOUBLE + (FixPoint::PRECISION / 2.0)))
        return std::numeric_limits<double>::quiet_NaN();

    /* deliberately primitive algorithm to make it easy to analyze and to make
     * it different from the real implementation */
    const double abs_dbl = std::abs(dbl);
    const double pre = std::trunc(abs_dbl);
    double below = pre;
    double above = pre + 1.0;

    for(uint8_t i = 0; i <= FixPoint::MAX_DECIMAL_VALUE; ++i)
    {
        const double temp = pre + FixPoint::PRECISION * i;

        if(temp < abs_dbl)
            below = temp;
        else if(temp > abs_dbl)
        {
            above = temp;
            break;
        }
        else
            return dbl;
    }

    return std::copysign(abs_dbl - below <= above - abs_dbl ? below : above,
                         dbl);
}

static void check_computed_expected_double(const double expected, const double input)
{
    expect_equal_doubles(expected, compute_expected_double(input), input);
}

void test_assert_integrity_of_expectation_computation()
{
    static constexpr double lower_int16_boundary =
        double(FixPoint::MIN_AS_INT16 - 1) + FixPoint::PRECISION / 2.0;
    static constexpr double upper_int16_boundary =
        double(FixPoint::MAX_AS_INT16 + 1) - FixPoint::PRECISION / 2.0;

    /* computations for integers */
    cppcut_assert_equal(int16_t(FixPoint::MIN_AS_INT16),
                        compute_expected_int16(FixPoint::MIN_AS_INT16));
    cppcut_assert_equal(int16_t(FixPoint::MAX_AS_INT16),
                        compute_expected_int16(FixPoint::MAX_AS_INT16));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(FixPoint::MIN_AS_INT16 - 1));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(FixPoint::MAX_AS_INT16 + 1));

    cppcut_assert_equal(int16_t(FixPoint::MIN_AS_INT16),
                        compute_expected_int16(double(FixPoint::MIN_AS_INT16)));
    cppcut_assert_equal(int16_t(FixPoint::MAX_AS_INT16),
                        compute_expected_int16(double(FixPoint::MAX_AS_INT16)));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(double(FixPoint::MIN_AS_INT16 - 1)));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(double(FixPoint::MAX_AS_INT16 + 1)));

    cppcut_assert_equal(int16_t(FixPoint::MIN_AS_INT16 - 1),
                        compute_expected_int16(lower_int16_boundary));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(std::nextafter(lower_int16_boundary,
                                                              std::numeric_limits<double>::lowest())));
    cppcut_assert_equal(int16_t(FixPoint::MAX_AS_INT16 + 1),
                        compute_expected_int16(upper_int16_boundary));
    cppcut_assert_equal(int16_t(INT16_MIN),
                        compute_expected_int16(std::nextafter(upper_int16_boundary,
                                                              std::numeric_limits<double>::max())));

    /* computations for doubles */
    static const double lower_double_boundary =
        FixPoint::MIN_AS_DOUBLE - FixPoint::PRECISION / 2.0;
    static const double upper_double_boundary =
        FixPoint::MAX_AS_DOUBLE + FixPoint::PRECISION / 2.0;

    expect_equal_doubles(lower_double_boundary, lower_int16_boundary);
    expect_equal_doubles(upper_double_boundary, upper_int16_boundary);

    check_computed_expected_double(FixPoint::MIN_AS_INT16, FixPoint::MIN_AS_INT16);
    check_computed_expected_double(FixPoint::MAX_AS_INT16, FixPoint::MAX_AS_INT16);
    check_computed_expected_double(std::numeric_limits<double>::quiet_NaN(),
                                   FixPoint::MIN_AS_INT16 - 1);
    check_computed_expected_double(std::numeric_limits<double>::quiet_NaN(),
                                   FixPoint::MAX_AS_INT16 + 1);

    check_computed_expected_double(double(FixPoint::MIN_AS_INT16 - 1) + FixPoint::PRECISION,
                                   std::nextafter(lower_double_boundary, 0.0));
    check_computed_expected_double(std::numeric_limits<double>::quiet_NaN(),
                                   lower_double_boundary);

    check_computed_expected_double(double(FixPoint::MAX_AS_INT16 + 1) - FixPoint::PRECISION,
                                   std::nextafter(upper_double_boundary, 0.0));
    check_computed_expected_double(std::numeric_limits<double>::quiet_NaN(),
                                   upper_double_boundary);
}

static void check_expected_conversion_to_native_types(double dbl)
{
    const auto value = FixPoint(dbl);
    const auto int_result = value.to_int16();
    const auto dbl_result = value.to_double();

    const int16_t expected_int16 = compute_expected_int16(dbl);
    const double expected_double = compute_expected_double(dbl);

    cppcut_assert_equal(expected_int16, int_result,
                        cut_message("Conversion failed for input %.20f", dbl));
    expect_equal_doubles(expected_double, dbl_result, dbl);
}

static void check_back_and_forth_conversions_are_stable(double dbl)
{
    const auto value = FixPoint(dbl);
    const auto dbl_result = value.to_double();
    const auto dbl_again = FixPoint(dbl_result).to_double();;

    expect_equal_doubles(dbl_result, dbl_again, dbl);

    const auto int_result = value.to_int16();
    const auto int_again = FixPoint(int_result).to_int16();

    static const char failmsg[] = "Multiple conversions failed for input %.20f";
    if(value.is_nan())
    {
        cppcut_assert_equal(int16_t(INT16_MIN), int_result, cut_message(failmsg, dbl));
        cppcut_assert_equal(int16_t(INT16_MIN), int_again, cut_message(failmsg, dbl));
    }
    else
    {
        if(int_result >= FixPoint::MIN_AS_INT16 && int_result <= FixPoint::MAX_AS_INT16)
            cppcut_assert_equal(int_result, int_again, cut_message(failmsg, dbl));
        else if(int_result == FixPoint::MIN_AS_INT16 - 1 ||
                int_result == FixPoint::MAX_AS_INT16 + 1)
            cppcut_assert_equal(int16_t(INT16_MIN), int_again, cut_message(failmsg, dbl));
        else
            cut_fail(failmsg, dbl);
    }
}

using knuth_lcg =
    std::linear_congruential_engine<uint64_t, 6364136223846793005U, 1442695040888963407U, 0U>;

static void random_tests_with_distribution(unsigned int count, knuth_lcg &prng,
                                           std::uniform_real_distribution<double> &&pdist)
{
    for(unsigned int i = 0; i < count; ++i)
    {
        const double dbl = pdist(prng);

        check_expected_conversion_to_native_types(dbl);
        check_back_and_forth_conversions_are_stable(dbl);
    }
}

void test_conversion_of_random_inputs_for_rounding()
{
    std::random_device rd;
    knuth_lcg prng(uint64_t(rd()) << 32 | rd());

    random_tests_with_distribution(30000, prng,
        std::move(std::uniform_real_distribution<double>(double(FixPoint::MIN_AS_INT16) - 2,
                                                         double(FixPoint::MAX_AS_INT16) + 2)));

    random_tests_with_distribution(5000, prng,
        std::move(std::uniform_real_distribution<double>(double(FixPoint::MIN_AS_INT16) - 5,
                                                         double(FixPoint::MIN_AS_INT16) + 5)));

    random_tests_with_distribution(5000, prng,
        std::move(std::uniform_real_distribution<double>(double(FixPoint::MAX_AS_INT16) - 5,
                                                         double(FixPoint::MAX_AS_INT16) + 5)));
}

}
