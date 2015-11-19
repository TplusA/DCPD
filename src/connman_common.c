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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include "connman_common.h"
#include "messages.h"

void connman_common_init_dict_from_temp_gvariant(GVariant *temp,
                                                 GVariantDict *dict)
{
    log_assert(temp != NULL);
    g_variant_dict_init(dict, temp);
    g_variant_unref(temp);
}

void connman_common_init_subdict(GVariant *tuple, GVariantDict *subdict,
                                 const char *subdict_name)
{
    GVariantDict dict;
    connman_common_init_dict_from_temp_gvariant(g_variant_get_child_value(tuple, 1),
                                                &dict);
    connman_common_init_dict_from_temp_gvariant(g_variant_dict_lookup_value(&dict, subdict_name,
                                                                            G_VARIANT_TYPE_VARDICT),
                                                subdict);
    g_variant_dict_clear(&dict);
}
