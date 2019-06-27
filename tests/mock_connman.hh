/*
 * Copyright (C) 2015, 2016, 2017, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_CONNMAN_HH
#define MOCK_CONNMAN_HH

#include "connman_scan.hh"
#include "connman_iter.h"
#include "mock_expectation.hh"

class MockConnman
{
  public:
    class SecurityIterData
    {
      public:
        const char *security_;

        SecurityIterData(const SecurityIterData &) = delete;
        SecurityIterData &operator=(const SecurityIterData &) = delete;
        SecurityIterData(SecurityIterData &&) = default;

        constexpr explicit SecurityIterData(const char *security):
            security_(security)
        {}
    };

    class ServiceIterData
    {
      public:
        const char *const technology_type_;
        const char *const ssid_;
        const int quality_;

        const SecurityIterData *const security_data_;
        const size_t security_data_count_;

        ServiceIterData(const ServiceIterData &) = delete;
        ServiceIterData &operator=(const ServiceIterData &) = delete;
        ServiceIterData(ServiceIterData &&) = default;

        constexpr explicit ServiceIterData(const char *technology_type,
                                           const char *ssid, int quality,
                                           const SecurityIterData &security_data):
            ServiceIterData(technology_type, ssid, quality, &security_data, 1)
        {}

        template <size_t N>
        constexpr explicit ServiceIterData(const char *technology_type,
                                           const char *ssid, int quality,
                                           const SecurityIterData (&security_data)[N]):
            ServiceIterData(technology_type, ssid, quality, security_data, N)
        {}

        constexpr explicit ServiceIterData(const char *technology_type,
                                           const char *ssid, int quality,
                                           const SecurityIterData *security_data,
                                           size_t security_data_count):
            technology_type_(technology_type),
            ssid_(ssid),
            quality_(quality),
            security_data_(security_data),
            security_data_count_(security_data_count)
        {}
    };

    template <typename T>
    class AnyIter
    {
      private:
        const T *const entries_;
        const size_t num_of_entries_;

        size_t current_index_;

      public:
        AnyIter(const AnyIter &) = delete;
        AnyIter &operator=(const AnyIter &) = delete;

        explicit AnyIter(const T *const entries, size_t num_of_entries):
            entries_(entries),
            num_of_entries_(num_of_entries),
            current_index_(0)
        {}

        const T &get()
        {
            cppcut_assert_operator(num_of_entries_, >, current_index_);
            return entries_[current_index_];
        }

        void rewind()
        {
            current_index_ = 0;
        }

        bool next()
        {
            if(current_index_ >= num_of_entries_)
                return false;

            if(++current_index_ >= num_of_entries_)
                return false;

            return true;
        }
    };

    static const SecurityIterData sec_psk_wps[2];
    static const SecurityIterData sec_psk;
    static const SecurityIterData sec_none;

  private:
    const ServiceIterData *iter_data_;
    size_t iter_data_count_;

  public:
    MockConnman(const MockConnman &) = delete;
    MockConnman &operator=(const MockConnman &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockConnman();
    ~MockConnman();

    void init();
    void check() const;

    using SurveyCallbackInvocation = void (*)(Connman::SiteSurveyDoneFn, Connman::SiteSurveyResult);

    void set_connman_service_iterator_data(const ServiceIterData &iter_data, size_t number_of_services);
    bool have_iter_data() const { return iter_data_ != nullptr; }
    struct ConnmanServiceIterator *do_service_iterator_get();

    void expect_connman_service_iterator_get(struct ConnmanServiceIterator *ret);
    void expect_connman_service_iterator_rewind(struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_next(bool ret, struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_free(struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_get_technology_type(const char *ret, struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_get_ssid(const char *ret, struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_get_strength(int ret, struct ConnmanServiceIterator *iter);
    void expect_connman_service_iterator_get_security_iterator(struct ConnmanServiceSecurityIterator *ret, struct ConnmanServiceIterator *iter, size_t *count);
    void expect_connman_security_iterator_next(bool ret, struct ConnmanServiceSecurityIterator *iter);
    void expect_connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter);
    void expect_connman_security_iterator_get_security(const char *ret, struct ConnmanServiceSecurityIterator *iter);

    void expect_connman_start_wlan_site_survey(bool ret);
    void expect_connman_start_wlan_site_survey(bool ret, SurveyCallbackInvocation callback_invocation, enum Connman::SiteSurveyResult callback_result);
};

extern MockConnman *mock_connman_singleton;

#endif /* !MOCK_CONNMAN_HH */
