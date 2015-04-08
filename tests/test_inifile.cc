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

#include <cppcutter.h>
#include <string.h>

#include "inifile.h"

/*!
 * \addtogroup inifile_tests Unit tests
 * \ingroup inifile
 *
 * INI file parser and generator unit tests.
 */
/*!@{*/

namespace inifile_tests
{

void cut_setup(void)
{
}

void cut_teardown(void)
{
}

/*!\test
 * Initialize INI file structure in memory.
 */
void test_create_empty_file_structure()
{
    struct ini_file ini;
    memset(&ini, 0xff, sizeof(ini));

    inifile_new(&ini);
    cppcut_assert_null(ini.sections_head);
    inifile_free(&ini);
}

/*!\test
 * Reading an empty file works and results in empty structures.
 */
void test_parse_empty_file_from_memory()
{
    struct ini_file ini;
    memset(&ini, 0xff, sizeof(ini));

    static const char dummy = '\0';
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, &dummy, 0));
    cppcut_assert_null(ini.sections_head);

    inifile_free(&ini);
}

};

/*!@}*/
