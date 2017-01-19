/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>

#include "configproxy.h"
#include "messages.h"
#include "dbus_iface_deep.h"
#include "dbus_common.h"

#define MAX_OWNERS              ((size_t)5)
#define MAX_ID_LENGTH           ((size_t)15)
#define MAX_DBUS_PATH_LENGTH    ((size_t)255)

static const char origin_this[] = "dcpd";

struct ConfigurationOwner
{
    char id[MAX_ID_LENGTH + 1];
    char dbus_path[256];
    char **keys;
    size_t number_of_keys;

    tdbusConfigurationRead *read_iface;
    tdbusConfigurationWrite *write_iface;
};

struct ConfigProxyData
{
    struct ConfigurationOwner owners[MAX_OWNERS];
    size_t next_free_owner;
};

static const struct ConfigurationOwner *
find_owner_by_id(const struct ConfigProxyData *data, const char *id)
{
    for(size_t i = 0; i < data->next_free_owner; ++i)
    {
        if(strcmp(data->owners[i].id, id) == 0)
            return &data->owners[i];
    }

    return NULL;
}

static const size_t is_owner_equal(const char *owner, const char *key_prefix)
{
    size_t i = 0;

    while(true)
    {
        if(key_prefix[i] == ':')
            return owner[i] == '\0' ? i + 1 : 0;

        if(key_prefix[i] != owner[i])
            return 0;

        ++i;
    }
}

static const struct ConfigurationOwner *
find_owner_by_key(const struct ConfigProxyData *data, const char *key,
                  const char **local_key)
{
    if(key[0] != '@' || key[1] == '\0' || key[1] == ':')
    {
        BUG("Key \"%s\" is not a fully qualified key", key);
        return NULL;
    }

    for(size_t i = 0; i < data->next_free_owner; ++i)
    {
        size_t prefix_len = is_owner_equal(data->owners[i].id, key + 1);

        if(prefix_len > 0)
        {
            *local_key = key + prefix_len + 1;
            return &data->owners[i];
        }
    }

    msg_error(0, LOG_ERR, "Owner of key \"%s\" not registered", key);

    return NULL;
}

static struct ConfigurationOwner *
allocate_owner(struct ConfigProxyData *data,
               const char *id, const char *dbus_dest, const char *dbus_path)
{
    if(data->next_free_owner >= MAX_OWNERS)
    {
        msg_error(0, LOG_ALERT, "Too many configuration owners");
        return NULL;
    }

    if(id[0] == '\0')
    {
        msg_error(0, LOG_ALERT, "Configuration owner ID empty");
        return NULL;
    }

    if(strlen(id) >= MAX_ID_LENGTH)
    {
        msg_error(0, LOG_ALERT, "Configuration owner ID too long");
        return NULL;
    }

    if(dbus_path[0] == '\0')
    {
        msg_error(0, LOG_ALERT, "Configuration owner path empty");
        return NULL;
    }

    if(strlen(dbus_path) >= MAX_DBUS_PATH_LENGTH)
    {
        msg_error(0, LOG_ALERT, "Configuration owner path too long");
        return NULL;
    }

    tdbusConfigurationRead *read_iface =
        dbus_get_configuration_read_iface(dbus_dest, dbus_path);
    tdbusConfigurationWrite *write_iface =
        dbus_get_configuration_write_iface(dbus_dest, dbus_path);

    if(read_iface == NULL || write_iface == NULL)
    {
        if(read_iface != NULL)
            g_object_unref(read_iface);

        if(write_iface != NULL)
            g_object_unref(write_iface);

        return NULL;
    }

    struct ConfigurationOwner *owner = &data->owners[data->next_free_owner++];

    strcpy(owner->id, id);
    strcpy(owner->dbus_path, dbus_path);
    owner->keys = NULL;
    owner->number_of_keys = 0;
    owner->read_iface = read_iface;
    owner->write_iface = write_iface;

    return owner;
}

static bool set_key_table(struct ConfigurationOwner *owner, char **keys)
{
    if(keys == NULL)
        return false;

    owner->keys = keys;

    for(char **key = keys; *key != NULL; ++key)
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "Registered key \"@%s:%s\"", owner->id, *key);
        ++owner->number_of_keys;
    }

    return owner->keys != NULL;
}

static void free_owner_struct(struct ConfigurationOwner *owner)
{
    log_assert(owner != NULL);

    owner->id[0] = '\0';
    owner->dbus_path[0] = '\0';

    if(owner->keys != NULL)
    {
        for(size_t i = 0; i < owner->number_of_keys; ++i)
            g_free(owner->keys[i]);

        g_free(owner->keys);
    }

    owner->keys = NULL;
    owner->number_of_keys = 0;

    if(owner->read_iface != NULL)
    {
        g_object_unref(owner->read_iface);
        owner->read_iface = NULL;
    }

    if(owner->write_iface != NULL)
    {
        g_object_unref(owner->write_iface);
        owner->write_iface = NULL;
    }
}

static inline void free_owner(struct ConfigProxyData *data, size_t i)
{
    free_owner_struct(&data->owners[i]);
}

static bool set(const char *origin, const struct ConfigurationOwner *owner,
                const char *key, GVariant *value)
{
    if(owner == NULL)
        return false;

    if(origin == NULL)
        origin = origin_this;

    GError *error = NULL;
    tdbus_configuration_write_call_set_value_sync(owner->write_iface,
                                                  origin, key, value,
                                                  NULL, &error);

    return dbus_common_handle_dbus_error(&error, "Set configuration value") == 0;
}

static GVariant *get(const struct ConfigurationOwner *owner, const char *key)
{
    if(owner == NULL)
        return NULL;

    GVariant *value = NULL;
    GError *error = NULL;
    tdbus_configuration_read_call_get_value_sync(owner->read_iface,
                                                 key, &value,
                                                 NULL, &error);

    dbus_common_handle_dbus_error(&error, "Read configuration value");

    return value;
}

static bool parse_uint32(const char *string, size_t len,
                         PatchUint32Fn patcher, uint32_t *dest)
{
    if(len == 0)
        goto error_exit_no_value;

    static const uint32_t max = UINT32_MAX / 10;

    uint32_t temp = 0;

    for(size_t i = 0; i < len; ++i)
    {
        const char ch = string[i];

        if(!isdigit(ch))
        {
            if(i == 0)
                goto error_exit_no_value;

            break;
        }

        if(temp > max)
        {
            msg_error(0, LOG_NOTICE, "Value too large for 32 bits");
            return false;
        }

        temp *= 10;
        temp += ch - '0';
    }

    *dest = temp;

    return patcher == NULL || patcher(dest);

error_exit_no_value:
    msg_error(0, LOG_NOTICE, "No number to parse");
    return false;
}

static bool is_buffer_big_enough(size_t dest_size, size_t src_size,
                                 const char *key)
{
    if(src_size <= dest_size)
        return true;

    msg_error(0, LOG_NOTICE,
              "Buffer too small to hold value for key \"%s\" (%zu < %zu)",
              key, dest_size, src_size);

    return false;
}

static ssize_t write_uint32(uint32_t value, PatchUint32Fn patcher,
                            char *dest, size_t dest_size, const char *key)
{
    if(patcher != NULL && !patcher(&value))
        return -1;

    const int len = snprintf(dest, dest_size, "%" PRIu32, value);
    return is_buffer_big_enough(dest_size, len + 1, key) ? len : -1;
}

static struct ConfigProxyData configproxy_data;

void configproxy_init(void)
{
    configproxy_data.next_free_owner = 0;
}

void configproxy_deinit(void)
{
    for(size_t i = 0; i < configproxy_data.next_free_owner; ++i)
        free_owner_struct(&configproxy_data.owners[i]);

    configproxy_data.next_free_owner = 0;
}

bool configproxy_register_configuration_owner(const char *id,
                                              const char *dbus_dest,
                                              const char *dbus_path)
{
    log_assert(id != NULL);
    log_assert(dbus_path != NULL);

    if(find_owner_by_id(&configproxy_data, id) != NULL)
    {
        BUG("Configuration owner \"%s\" already registered", id);
        return true;
    }

    struct ConfigurationOwner *owner =
        allocate_owner(&configproxy_data, id, dbus_dest, dbus_path);

    if(owner == NULL)
        return false;

    gchar *owner_id = NULL;
    gchar **keys = NULL;

    GError *error = NULL;
    tdbus_configuration_read_call_get_all_keys_sync(owner->read_iface,
                                                    &owner_id, &keys,
                                                    NULL, &error);

    if(dbus_common_handle_dbus_error(&error, "Read out configuration keys") < 0)
        goto error_exit;

    if(!set_key_table(owner, keys))
        goto error_exit;

    if(strcmp(owner_id, id) != 0)
    {
        msg_error(0, LOG_ALERT,
                  "Configuration owner \"%s\" != \"%s\"", owner_id, id);
        goto error_exit;
    }

    g_free(owner_id);

    msg_vinfo(MESSAGE_LEVEL_DIAG,
              "Registered %zu key%s for configuration owner \"%s\"",
              owner->number_of_keys, owner->number_of_keys != 1 ? "s" : "",
              owner->id);

    return true;

error_exit:
    if(owner_id != NULL)
        g_free(owner_id);

    --configproxy_data.next_free_owner;
    free_owner(&configproxy_data, configproxy_data.next_free_owner);

    return false;
}

bool configproxy_set_uint32(const char *origin, const char *key, uint32_t value)
{
    const char *local_key;
    const struct ConfigurationOwner *owner =
        find_owner_by_key(&configproxy_data, key, &local_key);

    return set(origin, owner, local_key,
               g_variant_new_variant(g_variant_new_uint32(value)));
}

bool configproxy_set_uint32_from_string(const char *origin, const char *key,
                                        const char *string, size_t len,
                                        PatchUint32Fn patcher)
{
    uint32_t value;

    if(parse_uint32(string, len, patcher, &value))
        return configproxy_set_uint32(origin, key, value);

    return false;
}

bool configproxy_set_string(const char *origin, const char *key, const char *value)
{
    const char *local_key;
    const struct ConfigurationOwner *owner =
        find_owner_by_key(&configproxy_data, key, &local_key);

    return set(origin, owner, local_key,
               g_variant_new_variant(g_variant_new_string(value)));
}

bool configproxy_set_value(const char *origin, const char *key, struct ConfigProxyVariant *value)
{
    const char *local_key;
    const struct ConfigurationOwner *owner =
        find_owner_by_key(&configproxy_data, key, &local_key);

    return set(origin, owner, local_key, (GVariant *)value);
}

struct ConfigProxyVariant *configproxy_get_value(const char *key)
{
    const char *local_key;
    const struct ConfigurationOwner *owner =
        find_owner_by_key(&configproxy_data, key, &local_key);

    return (struct ConfigProxyVariant *)get(owner, local_key);
}

ssize_t configproxy_get_value_as_string(const char *key,
                                        char *buffer, size_t buffer_size,
                                        PatchUint32Fn patcher)
{
    log_assert(buffer != NULL);
    log_assert(buffer_size > 0);

    GVariant *value = (GVariant *)configproxy_get_value(key);

    if(value != NULL &&
       g_variant_is_of_type(value, G_VARIANT_TYPE_VARIANT) &&
       g_variant_n_children(value) == 1)
    {
        /* descend into variants with one child */
        GVariant *temp = value;
        value = g_variant_get_child_value(temp, 0);
        g_variant_unref(temp);
    }

    if(value == NULL)
        return -1;

    ssize_t retval = -1;

    if(g_variant_is_of_type(value, G_VARIANT_TYPE_STRING))
    {
        gsize len;
        const gchar *v = g_variant_get_string(value, &len);

        if(v == NULL)
            BUG("Got NULL string value for key \"%s\"", key);
        else if(is_buffer_big_enough(buffer_size, len + 1, key))
        {
            memcpy(buffer, v, len);
            buffer[len] = '\0';
            retval = len;
        }
    }
    else if(g_variant_is_of_type(value, G_VARIANT_TYPE_UINT32))
        retval = write_uint32(g_variant_get_uint32(value), patcher,
                              buffer, buffer_size, key);
    else
        BUG("Unsupported type %s for key \"%s\"",
            g_variant_get_type_string(value), key);

    g_variant_unref(value);

    return retval;
}
