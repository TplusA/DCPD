/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MOCK_AUDIOPATH_DBUS_CC
#define MOCK_AUDIOPATH_DBUS_CC

#include <functional>

#include "de_tahifi_audiopath.h"
#include "gvariantwrapper.hh"
#include "mock_expectation.hh"

class MockAudiopathDBus
{
  public:
    using ManagerRequestSourceResult = std::tuple<std::string, bool, GError *>;
    using ManagerRequestSourceWaiting =
        std::function<void(tdbusaupathManager *, const gchar *, GCancellable *,
                           GAsyncReadyCallback, void *,
                           ManagerRequestSourceResult &&)>;

    MockAudiopathDBus(const MockAudiopathDBus &) = delete;
    MockAudiopathDBus &operator=(const MockAudiopathDBus &) = delete;

    class Expectation;
    typedef MockExpectationsTemplate<Expectation> MockExpectations;
    MockExpectations *expectations_;

    explicit MockAudiopathDBus();
    ~MockAudiopathDBus();

    void init();
    void check() const;

    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id);
    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, bool shall_fail);
    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, const ManagerRequestSourceWaiting &wait_for_result_fn);
    void expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, const ManagerRequestSourceWaiting &wait_for_result_fn, GVariantWrapper &&request_data);

    void expect_tdbus_aupath_manager_call_release_path(tdbusaupathManager *object, bool deactivate_player);
    void expect_tdbus_aupath_manager_call_release_path(tdbusaupathManager *object, bool deactivate_player, GVariantWrapper &&request_data);

    void expect_tdbus_aupath_manager_call_get_source_info_sync(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_source_name, const gchar *out_player_id, const gchar *out_dbusname, const gchar *out_dbuspath);

    void expect_tdbus_aupath_player_call_activate_sync(gboolean retval, tdbusaupathPlayer *object);
    void expect_tdbus_aupath_player_call_activate_sync(gboolean retval, tdbusaupathPlayer *object, GVariantWrapper &&request_data);
    void expect_tdbus_aupath_player_call_deactivate_sync(gboolean retval, tdbusaupathPlayer *object);
    void expect_tdbus_aupath_player_call_deactivate_sync(gboolean retval, tdbusaupathPlayer *object, GVariantWrapper &&request_data);
    void expect_tdbus_aupath_source_call_selected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id);
    void expect_tdbus_aupath_source_call_selected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id, GVariantWrapper &&request_data);
    void expect_tdbus_aupath_source_call_deselected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id);
    void expect_tdbus_aupath_source_call_deselected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id, GVariantWrapper &&request_data);

    static void aupath_manager_request_source_result(tdbusaupathManager *proxy,
                                                     GCancellable *cancellable,
                                                     GAsyncReadyCallback callback,
                                                     void *user_data,
                                                     ManagerRequestSourceResult &&result);
};

extern MockAudiopathDBus *mock_audiopath_dbus_singleton;

#endif /* !MOCK_AUDIOPATH_DBUS_CC */
