/*
 * Copyright (C) 2016--2021  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_mediaservices.hh"
#include "dcpregs_audiosources.hh"
#include "registers_priv.hh"
#include "dbus_common.h"
#include "dbus_iface_deep.h"
#include "actor_id.h"
#include "gvariantwrapper.hh"
#include "gerrorwrapper.hh"
#include "messages.h"

#include <unordered_map>
#include <sstream>
#include <cstring>

static bool delete_credentials(const char *service_id, bool logout_on_failure,
                               bool *delete_failed_ptr)
{
    GErrorWrapper error;
    gchar *dummy = nullptr;

    tdbus_credentials_write_call_delete_credentials_sync(dbus_get_credentials_write_iface(),
                                                         service_id,
                                                         "", &dummy,
                                                         nullptr, error.await());

    const bool delete_failed = error.log_failure("D-Bus: Delete credentials");

    if(delete_failed_ptr != nullptr)
        *delete_failed_ptr = delete_failed;

    if(delete_failed)
    {
        if(!logout_on_failure)
            return false;
    }
    else
    {
        if(dummy == nullptr || dummy[0] != '\0')
            BUG("Expected empty default user");

        g_free(dummy);

        if(delete_failed_ptr == nullptr && !delete_failed)
            Regs::AudioSources::set_have_credentials(service_id, false);
    }

    if(dbus_get_airable_sec_iface() != nullptr)
        tdbus_airable_call_external_service_logout_sync(dbus_get_airable_sec_iface(),
                                                        service_id, "",
                                                        true, ACTOR_ID_LOCAL_UI,
                                                        nullptr, error.await());
    else
        BUG("Cannot logout from %s, have no Airable D-Bus proxy", service_id);

    const bool logout_failed = error.log_failure("D-Bus: Service logout");
    return !(logout_failed || delete_failed);
}

static int set_credentials(const char *service_id,
                           const char *login, const char *password)
{
    bool delete_failed = true;
    (void)delete_credentials(service_id, true, &delete_failed);

    GErrorWrapper error;

    tdbus_credentials_write_call_set_credentials_sync(dbus_get_credentials_write_iface(),
                                                      service_id,
                                                      login, password, TRUE,
                                                      nullptr, error.await());

    const bool failed = error.log_failure("D-Bus: Set credentials");

    if(!failed)
        Regs::AudioSources::set_have_credentials(service_id, true);
    else if(!delete_failed)
        Regs::AudioSources::set_have_credentials(service_id, false);

    tdbus_airable_call_external_service_login_sync(dbus_get_airable_sec_iface(),
                                                   service_id, login, true,
                                                   ACTOR_ID_LOCAL_UI, nullptr, nullptr);

    return failed ? -1 : 0;
}

int Regs::MediaServices::DCP::write_106_media_service_list(const uint8_t *data,
                                                           size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 106 handler %p %zu", data, length);

    if(dbus_get_credentials_write_iface() == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Cannot write service credentials, no Airable D-Bus proxy");
        return -1;
    }

    if(length == 0)
    {
        Regs::get_data().register_changed_notification_fn(106);
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
        return delete_credentials(string_data, false, nullptr) ? 0 : -1;

    char password_buffer[256];
    size_t safe_password_length = password_length;

    if(safe_password_length >= sizeof(password_buffer))
        safe_password_length = sizeof(password_buffer) - 1;

    std::copy(password, password + safe_password_length, password_buffer);
    password_buffer[safe_password_length] = '\0';

    return set_credentials(string_data, login, password_buffer);
}

static const std::string *xml_escape_character(const char ch)
{
    static const std::unordered_map<char, const std::string> escapes =
    {
        {'&', "&amp;"},
        {'<',  "&lt;"},
        {'>',  "&gt;"},
        {'\'', "&apos;"},
        {'"',  "&quot;"},
    };

    const auto &it(escapes.find(ch));
    return it != escapes.end() ? &it->second : nullptr;
}

static void xml_escape(char *const buffer, const size_t buffer_size,
                       const char *const input)
{
    log_assert(input != nullptr);

    size_t out_pos = 0;

    for(size_t i = 0; out_pos < buffer_size; ++i)
    {
        const char ch = input[i];

        if(ch == '\0')
            break;

        const std::string *seq = xml_escape_character(ch);

        if(seq == nullptr)
            buffer[out_pos++] = ch;
        else if(seq->length() < buffer_size - out_pos)
        {
            std::copy(seq->begin(), seq->end(), &buffer[out_pos]);
            out_pos += seq->length();
        }
        else
        {
            std::fill(buffer + out_pos, buffer + buffer_size, 0);
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

static bool contains_string(GVariantIter *ctypes, const char *needle)
{
    const char *value;

    while(g_variant_iter_loop(ctypes, "&s", &value))
        if(strcmp(value, needle) == 0)
            return true;

    return false;
}

static bool fill_buffer_with_services(std::vector<uint8_t> &buffer,
                                      GVariantWrapper &&catinfo)
{
    bool retval = true;
    const size_t number_of_services = GVariantWrapper::get(catinfo) != nullptr
        ? g_variant_n_children(GVariantWrapper::get(catinfo))
        :0;

    if(number_of_services == 0)
    {
        static const std::string empty("<services count=\"0\"/>");
        std::copy(empty.begin(), empty.end(), std::back_inserter(buffer));
        return retval;
    }

    std::ostringstream os;
    os << "<services count=\"" << number_of_services << "\">";

    tdbuscredentialsRead *read_iface = dbus_get_credentials_read_iface();

    for(size_t i = 0; i < number_of_services; ++i)
    {
        GVariantWrapper id_and_name(
            g_variant_get_child_value(GVariantWrapper::get(catinfo), i),
            GVariantWrapper::Transfer::JUST_MOVE);

        const gchar *id;
        const gchar *name;
        GVariantIter *supported_credential_types = nullptr;

        g_variant_get(GVariantWrapper::get(id_and_name), "(&s&sas)",
                      &id, &name, &supported_credential_types);

        const bool has_oauth = contains_string(supported_credential_types, "oauth");
        g_variant_iter_free(supported_credential_types);
        supported_credential_types = nullptr;

        GVariant *temp = nullptr;
        char *default_user = nullptr;
        GErrorWrapper error;

        tdbus_credentials_read_call_get_credentials_sync(read_iface, id,
                                                         &temp,
                                                         &default_user,
                                                         nullptr, error.await());

        if(error.log_failure("D-Bus: Get credentials"))
        {
            retval = false;
            break;
        }

        GVariantWrapper credentials(temp);
        const size_t number_of_credentials = g_variant_n_children(GVariantWrapper::get(credentials));

        static char buffer_first[1024];
        static char buffer_second[1024];

        xml_escape(buffer_first,  sizeof(buffer_first),  id);
        xml_escape(buffer_second, sizeof(buffer_second), name);

        os << "<service id=\"" << buffer_first << "\" name=\"" << buffer_second
           << "\" has_oauth=\"" << (has_oauth ? "true" : "false") << "\"";

        if(number_of_credentials == 0)
            os << "/>";
        else
        {
            os << ">";

            for(size_t j = 0; j < number_of_credentials; ++j)
            {
                temp = g_variant_get_child_value(GVariantWrapper::get(credentials), j);
                GVariantWrapper login_and_password(temp, GVariantWrapper::Transfer::JUST_MOVE);

                const gchar *login;
                const gchar *password;
                g_variant_get(GVariantWrapper::get(login_and_password), "(&s&s)",
                              &login, &password);

                xml_escape(buffer_first,  sizeof(buffer_first),  login);
                xml_escape(buffer_second, sizeof(buffer_second), password);

                os << "<account login=\"" << buffer_first << "\""
                   << " password=\"" << buffer_second << "\""
                   << ((std::strcmp(login, default_user) == 0) ? " default=\"true\"" : "")
                   << "/>";
            }

            os << "</service>";
        }

        g_free(default_user);
    }

    os << "</services>";

    const auto &str(os.str());
    std::copy(str.begin(), str.end(), std::back_inserter(buffer));

    return retval;
}

bool Regs::MediaServices::DCP::read_106_media_service_list(std::vector<uint8_t> &buffer)
{
    log_assert(buffer.empty());

    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 106 handler");

    if(dbus_get_credentials_read_iface() == nullptr)
    {
        msg_error(0, LOG_ERR,
                  "Cannot read out service list, no Airable D-Bus proxy");
        return false;
    }

    GVariant *service_ids_and_names_variant = nullptr;
    GErrorWrapper error;

    tdbus_credentials_read_call_get_known_categories_sync(dbus_get_credentials_read_iface(),
                                                          &service_ids_and_names_variant,
                                                          nullptr, error.await());

    if(error.log_failure("D-Bus: Get categories"))
        return fill_buffer_with_services(buffer, GVariantWrapper(nullptr));
    else
        return fill_buffer_with_services(buffer,
                                         GVariantWrapper(service_ids_and_names_variant));
}
