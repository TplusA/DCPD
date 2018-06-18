/*
 * Copyright (C) 2017, 2018  T+A elektroakustik GmbH & Co. KG
 *
 * This file is part of TAPSwitch.
 *
 * TAPSwitch is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 3 as
 * published by the Free Software Foundation.
 *
 * TAPSwitch is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with TAPSwitch.  If not, see <http://www.gnu.org/licenses/>.
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cppcutter.h>
#include <string>
#include <tuple>

#include "mock_audiopath_dbus.hh"

enum class AudiopathFn
{
    manager_request_source,
    manager_get_source_info,
    player_activate,
    player_deactivate,
    source_selected,
    source_deselected,

    first_valid_audiopath_fn_id = manager_request_source,
    last_valid_audiopath_fn_id = source_deselected,
};

static std::ostream &operator<<(std::ostream &os, const AudiopathFn id)
{
    if(id < AudiopathFn::first_valid_audiopath_fn_id ||
       id > AudiopathFn::last_valid_audiopath_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case AudiopathFn::manager_request_source:
        os << "manager_request_source";
        break;

      case AudiopathFn::manager_get_source_info:
        os << "manager_get_source_info";
        break;

      case AudiopathFn::player_activate:
        os << "player_activate";
        break;

      case AudiopathFn::player_deactivate:
        os << "player_deactivate";
        break;

      case AudiopathFn::source_selected:
        os << "source_selected";
        break;

      case AudiopathFn::source_deselected:
        os << "source_deselected";
        break;
    }

    os << "()";

    return os;
}

class MockAudiopathDBus::Expectation
{
  public:
    struct Data
    {
        const AudiopathFn function_id_;

        bool ret_bool_;
        bool expecting_async_callback_fn_;
        void *arg_object_;
        std::string arg_source_id_;
        GVariantWrapper arg_request_data_;
        std::string out_source_name_;
        std::string out_player_id_;
        std::string out_dbusname_;
        std::string out_dbuspath_;
        bool out_switched_;
        ManagerRequestSourceWaiting manager_request_source_waiting_fn_;

        explicit Data(AudiopathFn fn):
            function_id_(fn),
            ret_bool_(false),
            expecting_async_callback_fn_(false),
            arg_object_(nullptr),
            out_switched_(false)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathManager *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.expecting_async_callback_fn_ = false;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathManager *object,
                         const char *out_player_id, bool out_switched):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.expecting_async_callback_fn_ = true;
        data_.out_player_id_ = out_player_id;
        data_.out_switched_ = out_switched;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathManager *object,
                         const char *out_player_id, bool out_switched,
                         const ManagerRequestSourceWaiting &wait_for_result_fn):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.expecting_async_callback_fn_ = true;
        data_.out_player_id_ = out_player_id;
        data_.out_switched_ = out_switched;
        data_.arg_object_ = static_cast<void *>(object);
        data_.manager_request_source_waiting_fn_ = wait_for_result_fn;;
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathManager *object,
                         const gchar *arg_source_id, const gchar *out_source_name,
                         const char *out_player_id, const gchar *out_dbusname,
                         const gchar *out_dbuspath):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_source_id_ = arg_source_id;
        data_.out_source_name_ = out_source_name;
        data_.out_player_id_ = out_player_id;
        data_.out_dbusname_ = out_dbusname;
        data_.out_dbuspath_ = out_dbuspath;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathPlayer *object):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathPlayer *object,
                         GVariantWrapper &&request_data):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        data_.arg_request_data_ = std::move(request_data);
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathSource *object,
                         const char *source_id):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        data_.arg_source_id_ = source_id;
    }

    explicit Expectation(AudiopathFn fn, bool retval, tdbusaupathSource *object,
                         const char *source_id, GVariantWrapper &&request_data):
        d(fn)
    {
        data_.ret_bool_ = retval;
        data_.arg_object_ = static_cast<void *>(object);
        data_.arg_source_id_ = source_id;
        data_.arg_request_data_ = std::move(request_data);
    }

    Expectation(Expectation &&) = default;
};


MockAudiopathDBus::MockAudiopathDBus()
{
    expectations_ = new MockExpectations();
}

MockAudiopathDBus::~MockAudiopathDBus()
{
    delete expectations_;
}

void MockAudiopathDBus::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockAudiopathDBus::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockAudiopathDBus::expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id)
{
    expectations_->add(Expectation(AudiopathFn::manager_request_source,
                                   true, object));
}

void MockAudiopathDBus::expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, bool shall_fail)
{
    expectations_->add(Expectation(AudiopathFn::manager_request_source,
                                   !shall_fail, object, out_player_id, out_switched));
}

void MockAudiopathDBus::expect_tdbus_aupath_manager_call_request_source(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_player_id, const gboolean out_switched, const ManagerRequestSourceWaiting &wait_for_result_fn)
{
    expectations_->add(Expectation(AudiopathFn::manager_request_source,
                                   true, object, out_player_id, out_switched,
                                   wait_for_result_fn));
}

void MockAudiopathDBus::expect_tdbus_aupath_manager_call_get_source_info_sync(tdbusaupathManager *object, const gchar *arg_source_id, const gchar *out_source_name, const gchar *out_player_id, const gchar *out_dbusname, const gchar *out_dbuspath)
{
    expectations_->add(Expectation(AudiopathFn::manager_get_source_info,
                                   true, object,
                                   arg_source_id, out_source_name,
                                   out_player_id, out_dbusname, out_dbuspath));
}

void MockAudiopathDBus::expect_tdbus_aupath_player_call_activate_sync(gboolean retval, tdbusaupathPlayer *object)
{
    expectations_->add(Expectation(AudiopathFn::player_activate,
                                   retval, object));
}

void MockAudiopathDBus::expect_tdbus_aupath_player_call_activate_sync(gboolean retval, tdbusaupathPlayer *object, GVariantWrapper &&request_data)
{
    expectations_->add(Expectation(AudiopathFn::player_activate,
                                   retval, object, std::move(request_data)));
}

void MockAudiopathDBus::expect_tdbus_aupath_player_call_deactivate_sync(gboolean retval, tdbusaupathPlayer *object)
{
    expectations_->add(Expectation(AudiopathFn::player_deactivate,
                                   retval, object));
}

void MockAudiopathDBus::expect_tdbus_aupath_player_call_deactivate_sync(gboolean retval, tdbusaupathPlayer *object, GVariantWrapper &&request_data)
{
    expectations_->add(Expectation(AudiopathFn::player_deactivate,
                                   retval, object, std::move(request_data)));
}

void MockAudiopathDBus::expect_tdbus_aupath_source_call_selected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id)
{
    expectations_->add(Expectation(AudiopathFn::source_selected,
                                   retval, object, arg_source_id));
}

void MockAudiopathDBus::expect_tdbus_aupath_source_call_selected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id, GVariantWrapper &&request_data)
{
    expectations_->add(Expectation(AudiopathFn::source_selected,
                                   retval, object, arg_source_id, std::move(request_data)));
}

void MockAudiopathDBus::expect_tdbus_aupath_source_call_deselected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id)
{
    expectations_->add(Expectation(AudiopathFn::source_deselected,
                                   retval, object, arg_source_id));
}

void MockAudiopathDBus::expect_tdbus_aupath_source_call_deselected_sync(gboolean retval, tdbusaupathSource *object, const gchar *arg_source_id, GVariantWrapper &&request_data)
{
    expectations_->add(Expectation(AudiopathFn::source_deselected,
                                   retval, object, arg_source_id, std::move(request_data)));
}


MockAudiopathDBus *mock_audiopath_dbus_singleton = nullptr;

static char extract_id(tdbusaupathPlayer *proxy)
{
    return reinterpret_cast<unsigned long>(proxy) & UINT8_MAX;
}

static char extract_id(tdbusaupathSource *proxy)
{
    return reinterpret_cast<unsigned long>(proxy) & UINT8_MAX;
}

static void check_request_data(const GVariantWrapper &expected_data,
                               GVariant *const arg_request_data,
                               bool auto_unref_data = true)
{
    cppcut_assert_not_null(arg_request_data);
    cut_assert_true(g_variant_is_of_type(arg_request_data, G_VARIANT_TYPE_VARDICT));

    g_variant_ref_sink(arg_request_data);

    if(expected_data != nullptr)
    {
        if(GVariantWrapper::get(expected_data) != arg_request_data)
            cut_assert_true(g_variant_equal(GVariantWrapper::get(expected_data),
                                            arg_request_data));
    }
    else
        cppcut_assert_equal(gsize(0), g_variant_n_children(arg_request_data));

    if(auto_unref_data)
        g_variant_unref(arg_request_data);
}

void tdbus_aupath_manager_call_request_source(tdbusaupathManager *proxy, const gchar *arg_source_id, GVariant *arg_request_data, GCancellable *cancellable, GAsyncReadyCallback callback, gpointer user_data)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::manager_request_source);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    check_request_data(expect.d.arg_request_data_, arg_request_data);

    if(expect.d.expecting_async_callback_fn_)
        cppcut_assert_not_null(reinterpret_cast<void *>(callback));
    else
        cppcut_assert_null(reinterpret_cast<void *>(callback));

    if(callback != nullptr)
    {
        GError *error = expect.d.ret_bool_
            ? nullptr
            : g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                          "Mock manager request source failure");
        MockAudiopathDBus::ManagerRequestSourceResult result(expect.d.out_player_id_,
                                                             expect.d.out_switched_,
                                                             error);

        if(cancellable != nullptr)
            g_object_ref(G_OBJECT(cancellable));

        if(expect.d.manager_request_source_waiting_fn_ != nullptr)
            expect.d.manager_request_source_waiting_fn_(proxy, arg_source_id, cancellable,
                                                        callback, user_data,
                                                        std::move(result));
        else
            MockAudiopathDBus::aupath_manager_request_source_result(proxy, cancellable,
                                                                    callback, user_data,
                                                                    std::move(result));
    }
}

void MockAudiopathDBus::aupath_manager_request_source_result(tdbusaupathManager *proxy,
                                                             GCancellable *cancellable,
                                                             GAsyncReadyCallback callback,
                                                             void *user_data,
                                                             ManagerRequestSourceResult &&result)
{
    if(cancellable != nullptr && g_cancellable_is_cancelled(cancellable))
    {
        GError *&error = std::get<2>(result);

        if(error != nullptr)
            g_error_free(error);

        error = g_error_new(G_IO_ERROR, G_IO_ERROR_CANCELLED,
                            "Mock request audio source canceled");
    }

    callback(reinterpret_cast<GObject *>(proxy),
             reinterpret_cast<GAsyncResult *>(&result), user_data);

    GError *error = std::get<2>(result);

    if(error != nullptr)
        g_error_free(error);

    if(cancellable != nullptr)
        g_object_unref(G_OBJECT(cancellable));
}

gboolean tdbus_aupath_manager_call_request_source_finish(tdbusaupathManager *proxy,
                                                         gchar **out_player_id,
                                                         gboolean *out_switched,
                                                         GAsyncResult *res,
                                                         GError **error)
{
    cppcut_assert_not_null(proxy);
    cppcut_assert_not_null(out_player_id);
    cppcut_assert_not_null(out_switched);
    cppcut_assert_not_null(res);

    const auto &result =
        *reinterpret_cast<const MockAudiopathDBus::ManagerRequestSourceResult *>(res);

    if(std::get<2>(result) == nullptr)
    {
        *out_player_id = g_strdup(std::get<0>(result).c_str());
        *out_switched = std::get<1>(result);
    }
    else
    {
        *out_player_id = nullptr;
        *out_switched = FALSE;
    }

    if(error != nullptr)
    {
        if(std::get<2>(result) != nullptr)
            *error = g_error_copy(std::get<2>(result));
        else
            *error = nullptr;
    }

    return TRUE;
}

gboolean tdbus_aupath_manager_call_get_source_info_sync(tdbusaupathManager *proxy,
                                                        const gchar *arg_source_id,
                                                        gchar **out_source_name,
                                                        gchar **out_player_id,
                                                        gchar **out_dbusname,
                                                        gchar **out_dbuspath,
                                                        GCancellable *cancellable,
                                                        GError **error)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::manager_get_source_info);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_source_id);
    cppcut_assert_equal(expect.d.arg_source_id_.c_str(), arg_source_id);
    cppcut_assert_not_null(out_source_name);
    cppcut_assert_not_null(out_player_id);
    cppcut_assert_not_null(out_dbusname);
    cppcut_assert_not_null(out_dbuspath);

    *out_source_name = g_strdup(expect.d.out_source_name_.c_str());
    *out_player_id = g_strdup(expect.d.out_player_id_.c_str());
    *out_dbusname = g_strdup(expect.d.out_dbusname_.c_str());
    *out_dbuspath = g_strdup(expect.d.out_dbuspath_.c_str());

    if(error != nullptr)
    {
        if(expect.d.ret_bool_)
            *error = nullptr;
        else
            *error = g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "Mock manager get source info failure");
    }

    return expect.d.ret_bool_;
}

gboolean tdbus_aupath_player_call_activate_sync(tdbusaupathPlayer *proxy, GVariant *arg_request_data, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::player_activate);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    check_request_data(expect.d.arg_request_data_, arg_request_data);

    if(error != nullptr)
    {
        if(expect.d.ret_bool_)
            *error = nullptr;
        else
            *error = g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "Mock player %c activation failure",
                                 extract_id(proxy));
    }

    return expect.d.ret_bool_;
}

gboolean tdbus_aupath_player_call_deactivate_sync(tdbusaupathPlayer *proxy, GVariant *arg_request_data, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::player_deactivate);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    check_request_data(expect.d.arg_request_data_, arg_request_data);

    if(error != nullptr)
    {
        if(expect.d.ret_bool_)
            *error = nullptr;
        else
            *error = g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "Mock player %c deactivation failure",
                                 extract_id(proxy));
    }

    return expect.d.ret_bool_;
}

gboolean tdbus_aupath_source_call_selected_sync(tdbusaupathSource *proxy, const gchar *arg_source_id, GVariant *arg_request_data, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::source_selected);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_source_id);
    cppcut_assert_equal(expect.d.arg_source_id_.c_str(), arg_source_id);
    check_request_data(expect.d.arg_request_data_, arg_request_data);

    if(error != nullptr)
    {
        if(expect.d.ret_bool_)
            *error = nullptr;
        else
            *error = g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "Mock source %c selection failure",
                                 extract_id(proxy));
    }

    return expect.d.ret_bool_;
}

gboolean tdbus_aupath_source_call_deselected_sync(tdbusaupathSource *proxy, const gchar *arg_source_id, GVariant *arg_request_data, GCancellable *cancellable, GError **error)
{
    const auto &expect(mock_audiopath_dbus_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, AudiopathFn::source_deselected);
    cppcut_assert_equal(expect.d.arg_object_, static_cast<void *>(proxy));
    cppcut_assert_not_null(arg_source_id);
    cppcut_assert_equal(expect.d.arg_source_id_.c_str(), arg_source_id);
    check_request_data(expect.d.arg_request_data_, arg_request_data);

    if(error != nullptr)
    {
        if(expect.d.ret_bool_)
            *error = nullptr;
        else
            *error = g_error_new(G_IO_ERROR, G_IO_ERROR_FAILED,
                                 "Mock source %c deselection failure",
                                 extract_id(proxy));
    }

    return expect.d.ret_bool_;
}
