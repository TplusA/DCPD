/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dcpregs_datetime.hh"

#include <chrono>
#include <sstream>
#include <iomanip>

bool Regs::DateTime::DCP::read_207_date_and_time(std::vector<uint8_t> &buffer)
{
    const auto t(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

    std::ostringstream os;
    os << std::put_time(std::localtime(&t),
                        "<datetime>"
                        "<day>%d</day>"
                        "<month>%m</month>"
                        "<year>%Y</year>"
                        "<hour>%H</hour>"
                        "<minute>%M</minute>"
                        "<second>%S</second>"
                        "<utc_offset>%z</utc_offset>"
                        "<tz>%Z</tz>"
                        "</datetime>");

    const auto &str(os.str());
    std::copy(str.begin(), str.end(), std::back_inserter(buffer));

    return true;
}
