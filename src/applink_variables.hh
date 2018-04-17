/*
 * Copyright (C) 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef APPLINK_VARIABLES_HH
#define APPLINK_VARIABLES_HH

#include <stdint.h>
#include <unistd.h>

/*!
 * \addtogroup app_link
 */
/*!@{*/

struct ApplinkVariable
{
    const char *name;
    uint16_t variable_id;
    const unsigned int number_of_request_parameters;
    const unsigned int number_of_answer_parameters;

    explicit ApplinkVariable(const char *n, uint16_t id,
                             unsigned int num_req, unsigned int num_ans):
        name(n),
        variable_id(id),
        number_of_request_parameters(num_req),
        number_of_answer_parameters(num_ans)
    {}
};

struct ApplinkVariableTable
{
    const struct ApplinkVariable *const variables;
    const size_t number_of_variables;
};

#ifdef __cplusplus
extern "C" {
#endif

const struct ApplinkVariable *
applink_variable_lookup(const struct ApplinkVariableTable *variables,
                        const char *variable_name);

const struct ApplinkVariable *
applink_variable_lookup_with_length(const struct ApplinkVariableTable *table,
                                    const char *variable_name, size_t length);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !APPLINK_VARIABLES_HH */
