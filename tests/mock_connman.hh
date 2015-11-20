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

#ifndef MOCK_CONNMAN_HH
#define MOCK_CONNMAN_HH

#include "connman.h"
#include "mock_expectation.hh"

class MockConnman
{
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

    using SurveyCallbackInvocation = void (*)(ConnmanSurveyDoneFn, enum ConnmanSiteScanResult);

    void expect_find_interface(struct ConnmanInterfaceData *ret, const char *mac_address);
    void expect_find_active_primary_interface(struct ConnmanInterfaceData *ret, const char *default_mac_address, const char *wired_mac_address, const char *wireless_mac_address);
    void expect_get_dhcp_mode(bool ret, struct ConnmanInterfaceData *iface_data);
    void expect_get_ipv4_address_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size);
    void expect_get_ipv4_netmask_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size);
    void expect_get_ipv4_gateway_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size);
    void expect_get_ipv4_primary_dns_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size);
    void expect_get_ipv4_secondary_dns_string(const char *ret_string, struct ConnmanInterfaceData *iface_data,  bool expect_null_pointer, size_t dest_size);
    void expect_get_wlan_security_type_string(bool ret, const char *ret_string, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size);
    void expect_get_wlan_ssid(const uint8_t *ret_bytes, size_t ret_bytes_size, struct ConnmanInterfaceData *iface_data, bool expect_null_pointer, size_t dest_size);
    void expect_free_interface_data(struct ConnmanInterfaceData *iface_data);

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
    void expect_connman_start_wlan_site_survey(bool ret, SurveyCallbackInvocation callback_invocation, enum ConnmanSiteScanResult callback_result);
};

extern MockConnman *mock_connman_singleton;

#endif /* !MOCK_CONNMAN_HH */
