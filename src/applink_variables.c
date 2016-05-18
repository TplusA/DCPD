/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "applink_variables.h"
#include "messages.h"

static int compare_variable_name(const void *a, const void *b)
{
    return strcmp(((const struct ApplinkVariable *)a)->name,
                  ((const struct ApplinkVariable *)b)->name);
}

const struct ApplinkVariable *
applink_variable_lookup(const struct ApplinkVariableTable *table,
                        const char *variable_name)
{
    static struct ApplinkVariable key;

    key.name = variable_name;

    const struct ApplinkVariable *result =
        bsearch(&key, table->variables, table->number_of_variables,
                sizeof(table->variables[0]), compare_variable_name);

    if(result == NULL)
        msg_error(0, LOG_NOTICE,
                  "Unknown applink variable \"%s\"", variable_name);

    return result;
}

const struct ApplinkVariable *
applink_variable_lookup_with_length(const struct ApplinkVariableTable *table,
                                    const char *variable_name, size_t length)
{
    if(length == 0 || length > 100)
    {
        msg_error(ERANGE, LOG_NOTICE,
                  "Unreasonable variable length %zu", length);
        return NULL;
    }

    char buffer[length + 1];

    memcpy(buffer, variable_name, length);
    buffer[length] = '\0';

    return applink_variable_lookup(table, buffer);
}
