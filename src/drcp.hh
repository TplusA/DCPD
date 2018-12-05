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

#ifndef DRCP_HH
#define DRCP_HH

#include <string>
#include <cstddef>

/*!
 * \addtogroup drcp Communication with DRCPD
 */
/*!@{*/

namespace Drcp
{

bool determine_xml_size(int in_fd, std::string &xml_string, size_t &expected_size);
bool read_xml(int in_fd, std::string &xml_string, const size_t expected_size);
void finish_request(int out_fd, bool is_ok);

bool read_size_from_fd(int in_fd, size_t &expected_size,
                       std::string &overhang_buffer);

}

/*!@}*/

#endif /* !DRCP_HH */
