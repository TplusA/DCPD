/*
 * Copyright (C) 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <string.h>
#include <errno.h>

#include "dcpregs_mediaservices.h"
#include "registers_priv.h"
#include "dynamic_buffer_util.h"
#include "credentials_dbus.h"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "actor_id.h"
#include "messages.h"

#define TRY_EMIT(BUF, FAILCODE, ...) \
    do \
    { \
        if(retval && !dynamic_buffer_printf((BUF), __VA_ARGS__)) \
        { \
            retval = false; \
            FAILCODE \
        } \
    }\
    while(0)

struct XmlEscapeSequence
{
    const char character;
    const char *const escape_sequence;
    const size_t escape_sequence_length;
};

static int delete_credentials(const char *service_id, bool logout_on_failure)
{
    GError *error = NULL;
    gchar *dummy = NULL;

    tdbus_credentials_write_call_delete_credentials_sync(dbus_get_credentials_write_iface(),
                                                         service_id,
                                                         "", &dummy,
                                                         NULL, &error);

    const int delete_ret = dbus_common_handle_dbus_error(&error, "Delete credentials");

    if(delete_ret < 0)
    {
        if(!logout_on_failure)
            return delete_ret;
    }
    else
    {
        if(dummy == NULL || dummy[0] != '\0')
            BUG("Expected empty default user");

        g_free(dummy);
    }

    tdbus_airable_call_external_service_logout_sync(dbus_get_airable_sec_iface(),
                                                    service_id, "",
                                                    true, ACTOR_ID_LOCAL_UI,
                                                    NULL, &error);

    const int logout_ret = dbus_common_handle_dbus_error(&error, "Service logout");

    if(logout_ret != 0)
        return logout_ret;
    else
        return delete_ret;
}

static int set_credentials(const char *service_id,
                           const char *login, const char *password)
{
    (void)delete_credentials(service_id, true);

    GError *error = NULL;

    tdbus_credentials_write_call_set_credentials_sync(dbus_get_credentials_write_iface(),
                                                      service_id,
                                                      login, password, TRUE,
                                                      NULL, &error);

    return dbus_common_handle_dbus_error(&error, "Set credentials");
}

int dcpregs_write_106_media_service_list(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 106 handler %p %zu", data, length);

    if(length == 0)
    {
        registers_get_data()->register_changed_notification_fn(106);
        return 0;
    }

    const char *string_data = (const char *)data;
    size_t i;

    for(i = 0; i < length && string_data[i] != '\0'; ++i)
        ;

    const char *const login = &string_data[++i];
    const size_t service_id_length = login - string_data - 1;

    if(service_id_length == 0)
    {
        msg_error(0, EINVAL, "Empty service ID sent to register 106");
        return -1;
    }


    for(/* nothing */; i < length && string_data[i] != '\0'; ++i)
        ;

    const char *const password = &string_data[++i];
    const size_t login_length = password - login - 1;

    for(/* nothing */; i < length && string_data[i] != '\0'; ++i)
        ;

    const size_t password_length = &string_data[i + 1] - password - 1;

    if(i < length && string_data[i] == '\0')
        ++i;

    if(login_length == 0 && password_length > 0)
    {
        msg_error(0, EINVAL, "Empty login sent to register 106");
        return -1;
    }

    if(login_length > 0 && password_length == 0)
    {
        msg_error(0, EINVAL, "Empty password sent to register 106");
        return -1;
    }

    if(i != length)
    {
        msg_error(0, EINVAL, "Malformed data written to register 106");
        return -1;
    }

    if(login_length == 0)
        return delete_credentials(string_data, false);

    char password_buffer[256];
    size_t safe_password_length = password_length;

    if(safe_password_length >= sizeof(password_buffer))
        safe_password_length = sizeof(password_buffer) - 1;

    memcpy(password_buffer, password, safe_password_length);
    password_buffer[safe_password_length] = '\0';

    return set_credentials(string_data, login, password_buffer);
}

static const struct XmlEscapeSequence *xml_escape_character(const char ch)
{
    static const struct XmlEscapeSequence escapes[] =
    {
#define MK_ESCAPE(CH, STR) \
        { \
            .character = (CH), \
            .escape_sequence = (STR), \
            .escape_sequence_length = sizeof(STR) - 1, \
        }

        MK_ESCAPE('&', "&amp;"),
        MK_ESCAPE('<',  "&lt;"),
        MK_ESCAPE('>',  "&gt;"),
        MK_ESCAPE('\'', "&apos;"),
        MK_ESCAPE('"',  "&quot;"),
    };

    for(size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); ++i)
    {
        if(ch == escapes[i].character)
            return &escapes[i];
    }

    return NULL;
}

static void xml_escape(char *const buffer, const size_t buffer_size,
                       const char *const input)
{
    log_assert(input != NULL);

    size_t out_pos = 0;

    for(size_t i = 0; out_pos < buffer_size; ++i)
    {
        const char ch = input[i];

        if(ch == '\0')
            break;

        const struct XmlEscapeSequence *seq = xml_escape_character(ch);

        if(seq == NULL)
            buffer[out_pos++] = ch;
        else if(seq->escape_sequence_length < buffer_size - out_pos)
        {
            memcpy(&buffer[out_pos], seq->escape_sequence, seq->escape_sequence_length);
            out_pos += seq->escape_sequence_length;
        }
        else
        {
            memset(&buffer[out_pos], 0, buffer_size - out_pos);
            out_pos = buffer_size;
            break;
        }
    }

    if(out_pos >= buffer_size)
    {
        msg_error(0, LOG_ERR, "Buffer too small for XML-escaping");
        out_pos = buffer_size - 1;
    }

    buffer[out_pos] = '\0';
}

static bool fill_buffer_with_services(struct dynamic_buffer *buffer,
                                      GVariant *service_ids_and_names_variant)
{
    const size_t number_of_services =
        g_variant_n_children(service_ids_and_names_variant);

    if(number_of_services == 0)
        return dynamic_buffer_printf(buffer, "<services count=\"0\"/>");

    bool retval = true;

    TRY_EMIT(buffer, return false;,
             "<services count=\"%zu\">", number_of_services);

    tdbuscredentialsRead *read_iface = dbus_get_credentials_read_iface();

    for(size_t i = 0; i < number_of_services; ++i)
    {
        GVariant *id_and_name =
            g_variant_get_child_value(service_ids_and_names_variant, i);

        const gchar *id;
        const gchar *name;
        g_variant_get(id_and_name, "(&s&s)", &id, &name);

        GVariant *credentials = NULL;
        char *default_user = NULL;
        GError *error = NULL;

        tdbus_credentials_read_call_get_credentials_sync(read_iface, id,
                                                         &credentials,
                                                         &default_user,
                                                         NULL, &error);

        if(dbus_common_handle_dbus_error(&error, "Get credentials") < 0)
        {
            g_variant_unref(id_and_name);
            retval = false;
            break;
        }

        const size_t number_of_credentials = g_variant_n_children(credentials);

        static char buffer_first[1024];
        static char buffer_second[1024];

        xml_escape(buffer_first,  sizeof(buffer_first),  id);
        xml_escape(buffer_second, sizeof(buffer_second), name);

        if(number_of_credentials == 0)
            TRY_EMIT(buffer, break;,
                     "<service id=\"%s\" name=\"%s\"/>", buffer_first, buffer_second);
        else
        {
            TRY_EMIT(buffer, break;,
                     "<service id=\"%s\" name=\"%s\">", buffer_first, buffer_second);

            for(size_t j = 0; j < number_of_credentials; ++j)
            {
                GVariant *login_and_password = g_variant_get_child_value(credentials, j);

                const gchar *login;
                const gchar *password;
                g_variant_get(login_and_password, "(&s&s)", &login, &password);

                xml_escape(buffer_first,  sizeof(buffer_first),  login);
                xml_escape(buffer_second, sizeof(buffer_second), password);

                TRY_EMIT(buffer, break;,
                         "<account login=\"%s\" password=\"%s\"%s/>",
                         buffer_first, buffer_second,
                         (strcmp(login, default_user) == 0) ? " default=\"true\"" : "");

                g_variant_unref(login_and_password);
            }

            TRY_EMIT(buffer, break;, "</service>");
        }

        g_variant_unref(credentials);
        g_free(default_user);

        g_variant_unref(id_and_name);
    }

    TRY_EMIT(buffer, return false;, "</services>");

    return retval;
}

bool dcpregs_read_106_media_service_list(struct dynamic_buffer *buffer)
{
    log_assert(dynamic_buffer_is_empty(buffer));

    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 106 handler");

    GVariant *service_ids_and_names_variant = NULL;
    GError *error = NULL;

    tdbus_credentials_read_call_get_known_categories_sync(dbus_get_credentials_read_iface(),
                                                          &service_ids_and_names_variant,
                                                          NULL, &error);
    if(dbus_common_handle_dbus_error(&error, "Get categories") < 0)
        return false;

    bool ret = fill_buffer_with_services(buffer, service_ids_and_names_variant);

    g_variant_unref(service_ids_and_names_variant);

    return ret;
}
