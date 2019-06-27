/*
 * Copyright (C) 2015, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "connman_iter.h"
#include "connman_common.h"
#include "dbus_iface_deep.h"
#include "messages.h"

#include <stdlib.h>

struct ConnmanServiceIterator
{
    GVariant *all_services;
    size_t count;

    size_t iter_pos;

    GVariant *current_service_tuple;
    GVariant *current_variant;
    GVariantDict dict;
};

struct ConnmanServiceSecurityIterator
{
    GVariant *all_securities;
    size_t count;

    size_t iter_pos;

    GVariant *current_security_string;
};

static inline void free_current_variant(struct ConnmanServiceIterator *iter)
{
    if(iter->current_variant != NULL)
        g_variant_unref(iter->current_variant);
}

static void free_service_iter_element_data(struct ConnmanServiceIterator *iter)
{
    if(iter->current_service_tuple != NULL)
        g_variant_unref(iter->current_service_tuple);

    free_current_variant(iter);

    g_variant_dict_clear(&iter->dict);
}

static void fill_service_iter(struct ConnmanServiceIterator *iter)
{
    free_service_iter_element_data(iter);

    iter->current_service_tuple = g_variant_get_child_value(iter->all_services, iter->iter_pos);
    iter->current_variant = NULL;
    connman_common_init_dict_from_temp_gvariant(
        g_variant_get_child_value(iter->current_service_tuple, 1),
        &iter->dict);
}

struct ConnmanServiceIterator *connman_service_iterator_get(void)
{
    struct ConnmanServiceIterator *iter = calloc(1, sizeof(*iter));
    if(iter == NULL)
    {
        msg_out_of_memory("WLAN service iterator");
        return NULL;
    }

    iter->all_services = connman_common_query_services(dbus_get_connman_manager_iface());

    if(iter->all_services != NULL)
    {
        iter->count = g_variant_n_children(iter->all_services);

        if(iter->count > 0)
        {
            fill_service_iter(iter);
            return iter;
        }
    }

    connman_service_iterator_free(iter);

    return NULL;
}

void connman_service_iterator_rewind(struct ConnmanServiceIterator *iter)
{
    log_assert(iter != NULL);

    if(iter->iter_pos > 0)
    {
        iter->iter_pos = 0;
        fill_service_iter(iter);
    }
}

bool connman_service_iterator_next(struct ConnmanServiceIterator *iter)
{
    if(iter != NULL && iter->iter_pos < iter->count)
    {
        if(++iter->iter_pos < iter->count)
        {
            fill_service_iter(iter);
            return true;
        }
    }

    return false;
}

void connman_service_iterator_free(struct ConnmanServiceIterator *iter)
{
    if(iter != NULL)
    {
        free_service_iter_element_data(iter);

        if(iter->all_services != NULL)
            g_variant_unref(iter->all_services);

        free(iter);
    }
}

static const char *get_string_value(struct ConnmanServiceIterator *iter,
                                    const char *key)
{
    log_assert(iter != NULL);
    log_assert(key != NULL);

    free_current_variant(iter);

    iter->current_variant =
        g_variant_dict_lookup_value(&iter->dict, key, G_VARIANT_TYPE_STRING);

    if(iter->current_variant != NULL)
        return g_variant_get_string(iter->current_variant, NULL);
    else
        return NULL;
}

const char *connman_service_iterator_get_service_name(struct ConnmanServiceIterator *iter)
{
    free_current_variant(iter);

    iter->current_variant =
        g_variant_get_child_value(iter->current_service_tuple, 0);

    if(iter->current_variant != NULL)
        return g_variant_get_string(iter->current_variant, NULL);
    else
        return NULL;
}

const char *connman_service_iterator_get_technology_type(struct ConnmanServiceIterator *iter)
{
    return get_string_value(iter, "Type");
}

const char *connman_service_iterator_get_ssid(struct ConnmanServiceIterator *iter)
{
    return get_string_value(iter, "Name");
}

int connman_service_iterator_get_strength(struct ConnmanServiceIterator *iter)
{
    free_current_variant(iter);

    iter->current_variant =
        g_variant_dict_lookup_value(&iter->dict, "Strength", G_VARIANT_TYPE_BYTE);

    if(iter->current_variant != NULL)
        return g_variant_get_byte(iter->current_variant);
    else
        return -1;
}

static inline void free_security_iter_element_data(struct ConnmanServiceSecurityIterator *iter)
{
    if(iter->current_security_string != NULL)
        g_variant_unref(iter->current_security_string);
}

static void fill_security_iter(struct ConnmanServiceSecurityIterator *iter)
{
    free_security_iter_element_data(iter);

    iter->current_security_string =
        g_variant_get_child_value(iter->all_securities, iter->iter_pos);
}

struct ConnmanServiceSecurityIterator *
connman_service_iterator_get_security_iterator(struct ConnmanServiceIterator *iter,
                                               size_t *count)
{
    log_assert(iter != NULL);

    if(count != NULL)
        *count = 0;

    struct ConnmanServiceSecurityIterator *sec_iter = calloc(1, sizeof(*sec_iter));
    if(sec_iter == NULL)
    {
        msg_out_of_memory("WLAN security iterator");
        return NULL;
    }

    sec_iter->all_securities =
        g_variant_dict_lookup_value(&iter->dict, "Security",
                                    G_VARIANT_TYPE_ARRAY);

    if(sec_iter->all_securities != NULL &&
       (sec_iter->count = g_variant_n_children(sec_iter->all_securities)) > 0)
    {
        if(count != NULL)
            *count = sec_iter->count;

        fill_security_iter(sec_iter);
        return sec_iter;
    }

    connman_security_iterator_free(sec_iter);

    return NULL;
}

bool connman_security_iterator_next(struct ConnmanServiceSecurityIterator *iter)
{
    if(iter != NULL && iter->iter_pos < iter->count)
    {
        if(++iter->iter_pos < iter->count)
        {
            fill_security_iter(iter);
            return true;
        }
    }

    return false;
}

void connman_security_iterator_free(struct ConnmanServiceSecurityIterator *iter)
{
    if(iter != NULL)
    {
        free_security_iter_element_data(iter);
        free(iter);
    }
}

const char *connman_security_iterator_get_security(struct ConnmanServiceSecurityIterator *iter)
{
    log_assert(iter != NULL);

    if(iter->current_security_string != NULL)
        return g_variant_get_string(iter->current_security_string, NULL);
    else
        return NULL;
}
