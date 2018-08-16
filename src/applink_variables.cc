/*
 * Copyright (C) 2015, 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "applink_variables.hh"
#include "messages.h"

#include <cstring>
#include <cerrno>

static int compare_variable_name(const void *a, const void *b)
{
    return strcmp(((const Applink::Variable *)a)->name,
                  ((const Applink::Variable *)b)->name);
}

const Applink::Variable *
Applink::VariableTable::lookup(const char *variable_name) const
{
    const Variable key(variable_name, 0, 0, 0);

    const auto *result =
        static_cast<const Variable *>(
            bsearch(&key, variables_, number_of_variables_,
                sizeof(variables_[0]), compare_variable_name));

    if(result == nullptr)
        msg_error(0, LOG_NOTICE,
                  "Unknown applink variable \"%s\"", variable_name);

    return result;
}

const Applink::Variable *
Applink::VariableTable::lookup(const char *variable_name,
                               size_t length) const
{
    if(length == 0 || length > 100)
    {
        msg_error(ERANGE, LOG_NOTICE,
                  "Unreasonable variable length %zu", length);
        return nullptr;
    }

    char buffer[length + 1];

    memcpy(buffer, variable_name, length);
    buffer[length] = '\0';

    return lookup(buffer);
}
