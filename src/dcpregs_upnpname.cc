/*
 * Copyright (C) 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_upnpname.h"
#include "shutdown_guard.h"
#include "messages.h"

#include <array>
#include <map>

enum class Key
{
    FRIENDLY_NAME_OVERRIDE,
    FRIENDLY_NAME_GIVEN_BY_USER,
    APPLIANCE_ID,
    DEVICE_UUID,

    LAST_KEY = DEVICE_UUID,

    INVALID,
    UNKNOWN,
};

static const std::array<const std::string, size_t(Key::LAST_KEY) + 1> keys
{
    "FRIENDLY_NAME_OVERRIDE",
    "FRIENDLY_NAME_GIVEN_BY_USER",
    "APPLIANCE_ID",
    "UUID",
};

using Values = std::map<Key, std::string>;

struct ParserContext
{
    const os_mapped_file_data &file;

    size_t line;
    size_t pos;
    size_t token_length;

    explicit ParserContext(const os_mapped_file_data &f):
        file(f),
        line(1),
        pos(0),
        token_length(0)
    {}
};

static ssize_t find_eol(const os_mapped_file_data &mapped_file,
                        const size_t pos)
{
    const char *const file = static_cast<const char *>(mapped_file.ptr);

    for(size_t i = pos; i < mapped_file.length; ++i)
    {
        if(file[i] == '\n')
            return i;
    }

    return -1;
}

static void skip_line(ParserContext &ctx, const ssize_t pos)
{
    const ssize_t i = pos >= 0 ? find_eol(ctx.file, pos) : -1;

    if(i >= 0)
    {
        ctx.pos = i + 1;
        ++ctx.line;
    }
    else
        ctx.pos = ctx.file.length;
}

static Key read_key_assignment(ParserContext &ctx)
{
    ctx.token_length = 0;

    /* shortest possible assignment is "A=''", consisting of 4 characters and a
     * terminating new line character */
    if(ctx.pos + 5 > ctx.file.length)
    {
        ctx.pos = ctx.file.length;
        msg_error(0, LOG_ERR,
                  "UPnP configuration file too short in line %zu", ctx.line);
        return Key::INVALID;
    }

    const char *const assignment = static_cast<const char *>(ctx.file.ptr) + ctx.pos;
    size_t key_index = 0;

    for(const auto k : keys)
    {
        if(k.compare(0, k.length(), assignment, k.length()) != 0 ||
           assignment[k.length()] != '=')
        {
            ++key_index;
            continue;
        }

        const ssize_t eolpos = find_eol(ctx.file, ctx.pos + k.length() + 2);

        if(assignment[k.length() + 1] != '\'' ||
           eolpos < 0 ||
           size_t(eolpos) <= ctx.pos + k.length() + 2 ||
           static_cast<const char *>(ctx.file.ptr)[eolpos - 1] != '\'')
        {
            msg_error(0, LOG_ERR,
                      "Unexpected file content in line %zu", ctx.line);
            skip_line(ctx, eolpos);
            return Key::INVALID;
        }

        ctx.pos += k.length() + 2;
        ctx.token_length = eolpos - ctx.pos - 1;

        return Key(key_index);
    }

    msg_error(0, LOG_ERR, "Unknown key in line %zu", ctx.line);
    skip_line(ctx, ctx.pos);

    return Key::UNKNOWN;
}

static bool read_value(ParserContext &ctx, std::string &value)
{
    if(ctx.token_length == 0)
        return true;

    const char *const token = static_cast<const char *>(ctx.file.ptr) + ctx.pos;
    size_t i = 0;

    value.reserve(ctx.token_length);

    while(i < ctx.token_length)
    {
        const char ch = token[i];

        if(ch != '\'')
        {
            value.push_back(ch);
            ++i;
        }
        else if(i + 4 < ctx.token_length && token[i + 1] == '\\' &&
                token[i + 2] == '\'' && token[i + 3] == '\'')
        {
            value.push_back('\'');
            i += 4;
        }
        else
        {
            msg_error(0, LOG_ERR,
                      "Unexpected end of assignment at position %zu", i);
            value.clear();
            return false;
        }
    }

    return true;
}

static void read_config_file(const char *filename, Values &values)
{
    struct os_mapped_file_data mapped_file;

    if(os_map_file_to_memory(&mapped_file, filename) < 0)
        return;

    ParserContext ctx(mapped_file);

    while(ctx.pos < mapped_file.length)
    {
        const auto key = read_key_assignment(ctx);

        if(key == Key::INVALID || key == Key::UNKNOWN)
            continue;

        if(!read_value(ctx, values[key]))
            values.erase(key);

        skip_line(ctx, ctx.pos + ctx.token_length);
    }

    os_unmap_file(&mapped_file);
}

static bool is_stored_name_equal(const Values &values,
                                 const char *new_name, size_t new_name_size)
{
    const auto val(values.find(Key::FRIENDLY_NAME_OVERRIDE));

    if(val == values.end())
        return false;

    if(val->second.length() > new_name_size)
        return false;

    if(val->second.compare(0, val->second.length(),
                           new_name, val->second.length()) != 0)
        return false;

    /* detect and allow zero-padding */
    for(size_t i = val->second.length(); i < new_name_size; ++i)
    {
        if(new_name[i] != '\0')
            return false;
    }

    return true;
}

static bool is_stored_value_equal(const Values &values, Key key,
                                  const std::string &v)
{
    const auto val(values.find(key));
    return (val != values.end()) ? val->second == v : false;
}

static void fill_output_buffer(std::string &buffer, const Values &values)
{
    static const char escaped_tick[] = "'\\''";

    for(auto it = values.begin(); it != values.end(); ++it)
    {
        buffer.append(keys[size_t(it->first)]);
        buffer.append("=\'");

        for(const char &ch : it->second)
        {
            if(ch != '\'')
                buffer.push_back(ch);
            else
                buffer.append(escaped_tick);
        }

        buffer.append("\'\n");
    }
}

/*!
 * Write configuration file for Flagpole.
 *
 * \retval  0 Succeeded.
 * \retval  1 File system changed, but failed writing configuration.
 * \retval -1 Failed, file system unchanged.
 */
static int write_config_file(const char *filename, const char *rcpath,
                             const Values &values,
                             struct ShutdownGuard *shutdown_guard)
{
    if(shutdown_guard_is_shutting_down_unlocked(shutdown_guard))
    {
        msg_info("Not writing UPnP configuration during shutdown.");
        return -1;
    }

    std::string buffer;
    fill_output_buffer(buffer, values);

    int fd = os_file_new(filename);
    if(fd < 0)
        return -1;

    const int ret = buffer.empty()
        ? 0
        : ((os_write_from_buffer(buffer.c_str(), buffer.length(), fd) == 0) ? 0 : 1);

    os_file_close(fd);

    if(ret != 0)
        os_file_delete(filename);

    os_sync_dir(rcpath);

    return ret;
}

static const char path_to_rcfile[] = "/var/local/etc";
static const char name_of_rcfile[] = "upnp_settings.rc";

struct UPnPNameData
{
    bool is_initialized;
    char rcfile[sizeof(path_to_rcfile) + sizeof(name_of_rcfile)];
    struct ShutdownGuard *shutdown_guard;

    void clear()
    {
        std::fill(rcfile, &rcfile[sizeof(rcfile)], '\0');
        shutdown_guard = nullptr;
        is_initialized = false;
    }
};

static UPnPNameData upnpname_private_data;

void dcpregs_upnpname_init(void)
{
    if(upnpname_private_data.is_initialized)
        return;

    std::copy(path_to_rcfile, path_to_rcfile + sizeof(path_to_rcfile) - 1,
              upnpname_private_data.rcfile);
    upnpname_private_data.rcfile[sizeof(path_to_rcfile) - 1] = '/';
    std::copy(name_of_rcfile, name_of_rcfile + sizeof(name_of_rcfile),
              upnpname_private_data.rcfile + sizeof(path_to_rcfile));

    upnpname_private_data.shutdown_guard = shutdown_guard_alloc("upnpname");

    upnpname_private_data.is_initialized = true;
}

void dcpregs_upnpname_deinit(void)
{
    shutdown_guard_free(&upnpname_private_data.shutdown_guard);
    upnpname_private_data.clear();
}

/*!
 * Read out UPnP friendly name of this device.
 *
 * \todo The name should be queried from Flagpole when it gets a proper D-Bus
 *       interface.
 *
 * \bug The hard-coded fallback name may become out of sync with Flagpole over
 *      time.
 *
 * \bug The whole approach taken by this implementation is wrong. The correct
 *      approach would be D-Bus only, not messing with configuration files and
 *      restarting systemd services. We did this to save some time.
 */
ssize_t dcpregs_read_88_upnp_friendly_name(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 88 handler %p %zu", response, length);

    Values values;
    read_config_file(upnpname_private_data.rcfile, values);

    const auto val(values.find(Key::FRIENDLY_NAME_OVERRIDE));

    if(val != values.end())
    {
        const size_t len = std::min(val->second.length(), length);

        if(len > 0)
            std::copy(val->second.begin(), val->second.begin() + len, response);

        return len;
    }

    static const char fallback_name[] = "T+A Streaming Board";

    const size_t len = std::min(sizeof(fallback_name) - 1, length);

    if(len > 0)
        std::copy(fallback_name, fallback_name + len, response);

    return len;
}

/*!
 * Write UPnP friendly name to configuration file and restart Flagpole.
 *
 * The Flagpole service is not restarted if the name is the same as already
 * configured.
 */
int dcpregs_write_88_upnp_friendly_name__v1_0_1(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 88 handler v1.0.1 %p %zu", data, length);

    Values values;
    read_config_file(upnpname_private_data.rcfile, values);

    if(is_stored_name_equal(values, (const char *)data, length))
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "UPnP name unchanged");
        return 0;
    }

    shutdown_guard_lock(upnpname_private_data.shutdown_guard);

    values[Key::FRIENDLY_NAME_OVERRIDE].clear();
    std::copy(data, data + length,
              std::back_inserter(values[Key::FRIENDLY_NAME_OVERRIDE]));
    values[Key::FRIENDLY_NAME_GIVEN_BY_USER] = "yes";

    const int result =
        write_config_file(upnpname_private_data.rcfile, path_to_rcfile,
                          values, upnpname_private_data.shutdown_guard);

    shutdown_guard_unlock(upnpname_private_data.shutdown_guard);

    if(result < 0)
        return -1;

    if(os_system(true, "/bin/systemctl restart flagpole") != EXIT_SUCCESS)
        return 0;

    return (result != 0) ? -1 : 0;
}

/*!
 * Write UPnP friendly name to configuration file and restart Flagpole.
 *
 * The Flagpole service is not restarted if the name is the same as already
 * configured.
 */
int dcpregs_write_88_upnp_friendly_name__v1_0_6(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 88 handler v1.0.6 %p %zu", data, length);

    Values values;
    read_config_file(upnpname_private_data.rcfile, values);

    const bool is_appliance_default_name = length > 0 && data[length - 1] == '\0';

    if(is_appliance_default_name)
        --length;

    if(is_stored_name_equal(values, (const char *)data, length))
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "UPnP name unchanged");
        return 0;
    }

    shutdown_guard_lock(upnpname_private_data.shutdown_guard);

    values[Key::FRIENDLY_NAME_OVERRIDE].clear();
    std::copy(data, data + length,
              std::back_inserter(values[Key::FRIENDLY_NAME_OVERRIDE]));
    values[Key::FRIENDLY_NAME_GIVEN_BY_USER] = is_appliance_default_name ? "no" : "yes";

    const int result =
        write_config_file(upnpname_private_data.rcfile, path_to_rcfile,
                          values, upnpname_private_data.shutdown_guard);

    shutdown_guard_unlock(upnpname_private_data.shutdown_guard);

    if(result < 0)
        return -1;

    if(os_system(true, "/bin/systemctl restart flagpole") != EXIT_SUCCESS)
        return 0;

    return (result != 0) ? -1 : 0;
}

static void set_variable(const Key key, const std::string &value)
{
    Values values;
    read_config_file(upnpname_private_data.rcfile, values);

    if(is_stored_value_equal(values, key, value))
        return;

    shutdown_guard_lock(upnpname_private_data.shutdown_guard);

    values[key] = value;

    const int result =
        write_config_file(upnpname_private_data.rcfile, path_to_rcfile,
                          values, upnpname_private_data.shutdown_guard);

    shutdown_guard_unlock(upnpname_private_data.shutdown_guard);

    if(result >= 0)
        os_system(true, "/bin/systemctl restart flagpole");
}

void dcpregs_upnpname_set_appliance_id(const std::string &appliance)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "Set UPnP appliance ID \"%s\"", appliance.c_str());

    set_variable(Key::APPLIANCE_ID, appliance);
}

void dcpregs_upnpname_set_device_uuid(const std::string &uuid)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "Set UPnP device UUID \"%s\"", uuid.c_str());

    set_variable(Key::DEVICE_UUID, uuid);
}

void dcpregs_upnpname_prepare_for_shutdown(void)
{
    (void)shutdown_guard_down(upnpname_private_data.shutdown_guard);
}
