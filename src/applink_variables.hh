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

#include <array>

#include <cstdint>
#include <unistd.h>

/*!
 * \addtogroup app_link
 */
/*!@{*/

namespace Applink
{

struct Variable
{
    const char *const name;
    const uint16_t variable_id;
    const unsigned int number_of_request_parameters;
    const unsigned int number_of_answer_parameters;

    explicit Variable(const char *n, uint16_t id,
                      unsigned int num_req, unsigned int num_ans):
        name(n),
        variable_id(id),
        number_of_request_parameters(num_req),
        number_of_answer_parameters(num_ans)
    {}
};

class VariableTable
{
  private:
    const Variable *const variables_;
    const size_t number_of_variables_;

  public:
    VariableTable(const VariableTable &) = delete;
    VariableTable &operator=(const VariableTable &) = delete;

    template <size_t N>
    explicit VariableTable(const std::array<Variable, N> &data):
        variables_(data.data()),
        number_of_variables_(N)
    {}

    const Variable *lookup(const char *variable_name) const;
    const Variable *lookup(const char *variable_name, size_t length) const;
};

}

/*!@}*/

#endif /* !APPLINK_VARIABLES_HH */
