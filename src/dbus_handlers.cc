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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cmath>
#include <string.h>
#include <errno.h>

#include "dbus_handlers.h"
#include "dcpregs_audiosources.h"
#include "dcpregs_networkconfig.h"
#include "dcpregs_upnpname.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_playstream.h"
#include "dcpregs_status.h"
#include "volume_control.hh"
#include "smartphone_app_send.h"
#include "configproxy.h"
#include "stream_id.h"
#include "actor_id.h"
#include "messages.h"

static void unknown_signal(const char *iface_name, const char *signal_name,
                           const char *sender_name)
{
    msg_error(ENOSYS, LOG_NOTICE, "Got unknown signal %s.%s from %s",
              iface_name, signal_name, sender_name);
}

static void check_parameter_assertions(GVariant *parameters,
                                       guint expected_number_of_parameters)
{
    /* we may use #log_assert() here because the GDBus code is supposed to do
     * any type checks before calling us---here, we just make sure we can
     * trust those type checks */
    log_assert(g_variant_type_is_tuple(g_variant_get_type(parameters)));
    log_assert(g_variant_n_children(parameters) == expected_number_of_parameters);
}

void dbussignal_logind_manager(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data)
{
    static const char iface_name[] = "org.freedesktop.login1.Manager";

    if(strcmp(signal_name, "PrepareForShutdown") == 0)
    {
        check_parameter_assertions(parameters, 1);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        gboolean is_active = g_variant_get_boolean(val);
        g_variant_unref(val);

        const auto *const iface =
            static_cast<const struct dbussignal_shutdown_iface *>(user_data);

        if(!iface->is_inhibitor_lock_taken())
            msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                      "Shutting down, but having no inhibit lock");

        dcpregs_filetransfer_prepare_for_shutdown();
        dcpregs_networkconfig_prepare_for_shutdown();
        dcpregs_upnpname_prepare_for_shutdown();

        if(!is_active)
        {
            msg_error(0, LOG_NOTICE,
                      "Funny PrepareForShutdown message, asking for restart");
            dcpregs_status_set_reboot_required();
        }

        /*
         * Tell the slave that we are about to shut down now. It will wait for
         * a few seconds before really cutting the power.
         */
        dcpregs_status_set_ready_to_shutdown();

        /*
         * This must be last because the D-Bus inhibit lock is going to be
         * released by this function. When this function returns, communication
         * with dcpspi may not be possible anymore.
         */
        iface->allow_shutdown();
    }
    else if(strcmp(signal_name, "SeatNew") == 0)
    {
        /* actively ignore irrelevant known signals */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_file_transfer(GDBusProxy *proxy, const gchar *sender_name,
                              const gchar *signal_name, GVariant *parameters,
                              gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.FileTransfer";

    if(strcmp(signal_name, "Progress") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint32_t tick = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        uint32_t total_ticks = g_variant_get_uint32(val);
        g_variant_unref(val);

        dcpregs_filetransfer_progress_notification(xfer_id, tick, total_ticks);
    }
    else if(strcmp(signal_name, "Done") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint32_t xfer_id = g_variant_get_uint32(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 1);
        uint8_t error_code_raw = g_variant_get_byte(val);
        g_variant_unref(val);

        val = g_variant_get_child_value(parameters, 2);
        gsize path_length;
        const gchar *path = g_variant_get_string(val, &path_length);

        enum DBusListsErrorCode error_code =
            (error_code_raw <= LIST_ERROR_LAST_ERROR_CODE
             ? (enum DBusListsErrorCode)error_code_raw
             : LIST_ERROR_INTERNAL);

        dcpregs_filetransfer_done_notification(xfer_id, error_code,
                                               path_length > 0 ? path : NULL);

        g_variant_unref(val);
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_splay_playback(GDBusProxy *proxy, const gchar *sender_name,
                               const gchar *signal_name, GVariant *parameters,
                               gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.Streamplayer.Playback";

    if(strcmp(signal_name, "NowPlaying") == 0)
    {
        /* some stream started or continued playing */
        check_parameter_assertions(parameters, 5);

        GVariant *val = g_variant_get_child_value(parameters, 0);
        uint16_t stream_id = g_variant_get_uint16(val);
        g_variant_unref(val);

        dcpregs_playstream_start_notification(stream_id,
                                              g_variant_get_child_value(parameters, 1));
    }
    else if(strcmp(signal_name, "Stopped") == 0 ||
            strcmp(signal_name, "StoppedWithError") == 0)
    {
        /* stream stopped playing */
        dcpregs_playstream_stop_notification();
    }
    else if(strcmp(signal_name, "MetaDataChanged") == 0 ||
            strcmp(signal_name, "PositionChanged") == 0 ||
            strcmp(signal_name, "SpeedChanged") == 0 ||
            strcmp(signal_name, "Paused") == 0)
    {
        /* ignore */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_set_stream_info(tdbusdcpdPlayback *object,
                                    GDBusMethodInvocation *invocation,
                                    guint16 raw_stream_id,
                                    const gchar *title, const gchar *url)
{
    if((raw_stream_id & STREAM_ID_SOURCE_MASK) == STREAM_ID_SOURCE_INVALID)
    {
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_INVALID_ARGS,
                                              "Invalid source in stream ID");
        return TRUE;
    }

    const bool clear_info =
        ((raw_stream_id & STREAM_ID_COOKIE_MASK) == STREAM_ID_COOKIE_INVALID ||
         url[0] == '\0');

    if(clear_info)
    {
        raw_stream_id &= STREAM_ID_SOURCE_MASK;
        raw_stream_id |= STREAM_ID_COOKIE_INVALID;
    }

    dcpregs_playstream_set_title_and_url(raw_stream_id, title, url);

    tdbus_dcpd_playback_complete_set_stream_info(object, invocation);

    return TRUE;
}

void dbussignal_audiopath_manager(GDBusProxy *proxy, const gchar *sender_name,
                                  const gchar *signal_name, GVariant *parameters,
                                  gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.AudioPath.Manager";

    if(strcmp(signal_name, "PathAvailable") == 0)
    {
        const gchar *source_id;
        const gchar *player_id;

        g_variant_get(parameters, "(&s&s)", &source_id, &player_id);
        dcpregs_audiosources_source_available(source_id);
    }
    else if(strcmp(signal_name, "PathActivated") == 0)
    {
        const gchar *source_id;
        const gchar *player_id;

        g_variant_get(parameters, "(&s&s)", &source_id, &player_id);
        dcpregs_audiosources_selected_source(source_id);
    }
    else if(strcmp(signal_name, "PlayerRegistered") == 0)
    {
        /* ignore */
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_audiopath_source_selected(tdbusaupathSource *object,
                                              GDBusMethodInvocation *invocation,
                                              const char *source_id,
                                              gpointer user_data)
{
    msg_info("Selected source \"%s\"", source_id);
    dcpregs_playstream_select_source();
    tdbus_aupath_source_complete_selected(object, invocation);
    return TRUE;
}

gboolean dbusmethod_audiopath_source_deselected(tdbusaupathSource *object,
                                                GDBusMethodInvocation *invocation,
                                                const char *source_id,
                                                gpointer user_data)
{
    msg_info("Deselected source \"%s\"", source_id);
    dcpregs_playstream_deselect_source();
    tdbus_aupath_source_complete_deselected(object, invocation);
    return TRUE;
}

gboolean dbusmethod_mixer_get_controls(tdbusmixerVolume *object,
                                       GDBusMethodInvocation *invocation,
                                       gpointer user_data)
{
    GVariantBuilder builder;
    g_variant_builder_init(&builder, G_VARIANT_TYPE("a(qssddddddy)"));

    const auto &controls(Mixer::VolumeControls::get_singleton());

    for(const auto &ctrl : *controls.first)
    {
        const auto *const props(ctrl->get_properties());

        if(props != nullptr)
        {
            const auto &settings(ctrl->get_settings());

            g_variant_builder_add(&builder, "(qssddddddy)",
                                  ctrl->id_, props->name_.c_str(),
                                  scale_to_string(props->scale_),
                                  props->volume_min_, props->volume_max_,
                                  props->volume_step_,
                                  props->min_db_, props->max_db_,
                                  settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                  settings.is_muted_.pick(1, 0, 2));
        }
    }

    tdbus_mixer_volume_complete_get_controls(object, invocation,
                                             g_variant_builder_end(&builder));

    return TRUE;
}

gboolean dbusmethod_mixer_get_master(tdbusmixerVolume *object,
                                     GDBusMethodInvocation *invocation,
                                     gpointer user_data)
{
    const auto &controls(Mixer::VolumeControls::get_singleton());
    const auto *const master(controls.first->get_master());

    if(master == nullptr)
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Have no master volume control");

    else
    {
        const auto *const props(master->get_properties());

        if(props == nullptr)
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Master volume control not configured");
        else
        {
            const auto &settings(master->get_settings());

            tdbus_mixer_volume_complete_get_master(object, invocation,
                    master->id_, props->name_.c_str(),
                    scale_to_string(props->scale_),
                    props->volume_min_, props->volume_max_,
                    props->volume_step_,
                    props->min_db_, props->max_db_,
                    settings.volume_.get(std::numeric_limits<double>::quiet_NaN()),
                    settings.is_muted_.pick(1, 0, 2));
        }
    }

    return TRUE;
}

gboolean dbusmethod_mixer_set(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gdouble volume, gboolean is_muted,
                              gpointer user_data)
{
    switch(Mixer::VolumeControls::get_singleton().first->request(id, volume, is_muted))
    {
      case Mixer::VolumeControls::Result::OK:
      case Mixer::VolumeControls::Result::IGNORED:
        tdbus_mixer_volume_complete_set(object, invocation);
        break;

      case Mixer::VolumeControls::Result::UNKNOWN_ID:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Cannot set unknown control ID %u",
                                              id);
        break;
    }

    return TRUE;
}

gboolean dbusmethod_mixer_get(tdbusmixerVolume *object,
                              GDBusMethodInvocation *invocation,
                              guint16 id, gpointer user_data)
{
    const Mixer::VolumeSettings *values;

    switch(Mixer::VolumeControls::get_singleton().first->get_current_values(id, values))
    {
      case Mixer::VolumeControls::Result::OK:
        if(values->volume_.is_known() && values->is_muted_.is_known())
            tdbus_mixer_volume_complete_get(object, invocation,
                                            values->volume_.get(std::numeric_limits<double>::quiet_NaN()),
                                            values->is_muted_.pick(1, 0 ,2));
        else
            g_dbus_method_invocation_return_error(invocation,
                                                  G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                                  "Values for control ID %u not known",
                                                  id);

        break;

      case Mixer::VolumeControls::Result::IGNORED:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Failed getting values for control ID %u",
                                              id);
        break;

      case Mixer::VolumeControls::Result::UNKNOWN_ID:
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Cannot get values for unknown control ID %u",
                                              id);
        break;
    }

    return TRUE;
}

void dbussignal_airable(GDBusProxy *proxy, const gchar *sender_name,
                        const gchar *signal_name, GVariant *parameters,
                        gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.Airable";

    if(strcmp(signal_name, "ExternalServiceLoginStatus") == 0)
    {
        check_parameter_assertions(parameters, 5);

        const gchar *service_id;
        const gchar *info;
        uint8_t actor_id;
        gboolean is_login;
        gboolean has_failed;

        g_variant_get(parameters, "(&sybb&s)",
                      &service_id, &actor_id, &is_login, &has_failed, &info);

        if(!has_failed)
            dcpregs_audiosources_set_login_state(service_id, is_login);

        if(actor_id != ACTOR_ID_SMARTPHONE_APP && !has_failed)
        {
            auto *data = static_cast<struct smartphone_app_connection_data *>(user_data);

            if(is_login)
                appconn_send_airable_service_logged_in(data, service_id, info);
            else
                appconn_send_airable_service_logged_out(data, service_id, info);
        }
        else
        {
            /* ignore silently, not interesting at the moment */
        }
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

void dbussignal_artcache_monitor(GDBusProxy *proxy, const gchar *sender_name,
                                 const gchar *signal_name, GVariant *parameters,
                                 gpointer user_data)
{
    static const char iface_name[] = "de.tahifi.ArtCache.Monitor";

    if(strcmp(signal_name, "Associated") == 0)
        check_parameter_assertions(parameters, 2);
    else if(strcmp(signal_name, "Removed") == 0)
    {
        check_parameter_assertions(parameters, 1);
        dcpregs_playstream_cover_art_notification(g_variant_get_child_value(parameters, 0));
    }
    else if(strcmp(signal_name, "Added") == 0)
    {
        check_parameter_assertions(parameters, 3);

        GVariant *stream_key_variant = NULL;
        uint8_t stream_key_priority;
        gboolean is_updated;

        g_variant_get(parameters, "(@ayyb)",
                      &stream_key_variant, &stream_key_priority, &is_updated);

        if(is_updated)
            dcpregs_playstream_cover_art_notification(stream_key_variant);
        else
            g_variant_unref(stream_key_variant);
    }
    else if(strcmp(signal_name, "Failed") == 0)
    {
        check_parameter_assertions(parameters, 3);
        dcpregs_playstream_cover_art_notification(g_variant_get_child_value(parameters, 0));
    }
    else
        unknown_signal(iface_name, signal_name, sender_name);
}

gboolean dbusmethod_configproxy_register(tdbusConfigurationProxy *object,
                                         GDBusMethodInvocation *invocation,
                                         const gchar *id, const gchar *path,
                                         void *user_data)
{
    const char *dest =
        g_dbus_message_get_sender(g_dbus_method_invocation_get_message(invocation));

    if(configproxy_register_configuration_owner(id, dest, path))
        tdbus_configuration_proxy_complete_register(object, invocation);
    else
        g_dbus_method_invocation_return_error(invocation,
                                              G_DBUS_ERROR, G_DBUS_ERROR_FAILED,
                                              "Failed registering configuration owner \"%s\"",
                                              id);

    return TRUE;
}

static enum MessageVerboseLevel do_set_debug_level(const char *new_level_name,
                                                   bool must_be_proper_name)
{
    static enum MessageVerboseLevel default_level = MESSAGE_LEVEL_IMPOSSIBLE;

    if(default_level == MESSAGE_LEVEL_IMPOSSIBLE)
        default_level = msg_get_verbose_level();

    enum MessageVerboseLevel old_level = msg_get_verbose_level();
    enum MessageVerboseLevel new_level;

    if(new_level_name == NULL || new_level_name[0] == '\0')
    {
        if(must_be_proper_name)
            new_level = old_level = MESSAGE_LEVEL_IMPOSSIBLE;
        else
        {
            new_level = old_level;
            new_level_name = msg_verbose_level_to_level_name(new_level);
        }
    }
    else if(strcmp(new_level_name, "default") == 0)
    {
        new_level = default_level;
        new_level_name = msg_verbose_level_to_level_name(new_level);
    }
    else
    {
        new_level = msg_verbose_level_name_to_level(new_level_name);

        if(new_level == MESSAGE_LEVEL_IMPOSSIBLE)
            old_level = MESSAGE_LEVEL_IMPOSSIBLE;
    }

    if(new_level != old_level)
    {
        msg_vinfo(MESSAGE_LEVEL_INFO_MIN,
                  "Set debug level \"%s\"", new_level_name);
        msg_set_verbose_level(new_level);
    }
    else if(old_level == MESSAGE_LEVEL_IMPOSSIBLE)
        msg_error(0, LOG_ERR, "Log level \"%s\" invalid", new_level_name);

    return old_level;
}

gboolean dbusmethod_debug_logging_debug_level(tdbusdebugLogging *object,
                                              GDBusMethodInvocation *invocation,
                                              const gchar *arg_new_level,
                                              void *user_data)
{
    const enum MessageVerboseLevel old_level =
        do_set_debug_level(arg_new_level, false);
    const char *name = msg_verbose_level_to_level_name(old_level);

    if(name == NULL)
        name = "";

    tdbus_debug_logging_complete_debug_level(object, invocation, name);

    return TRUE;
}

gboolean dbusmethod_debug_logging_config_set_level(tdbusdebugLoggingConfig *object,
                                                   GDBusMethodInvocation *invocation,
                                                   const gchar *arg_new_level,
                                                   void *user_data)
{
    const enum MessageVerboseLevel old_level =
        do_set_debug_level(arg_new_level, true);

    tdbus_debug_logging_config_complete_set_global_debug_level(object, invocation);

    if(old_level != MESSAGE_LEVEL_IMPOSSIBLE)
        tdbus_debug_logging_config_emit_global_debug_level_changed(object,
                                                                   arg_new_level);

    return TRUE;
}
