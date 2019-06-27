/*
 * Copyright (C) 2015, 2016, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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
