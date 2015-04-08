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

#include "mock_messages.hh"

/*!
 * \addtogroup inifile_tests Unit tests
 * \ingroup inifile
 *
 * INI file parser and generator unit tests.
 */
/*!@{*/

namespace inifile_tests
{

static MockMessages *mock_messages;

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;
}

void cut_teardown(void)
{
    mock_messages->check();

    mock_messages_singleton = nullptr;

    delete mock_messages;

    mock_messages = nullptr;
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
    cppcut_assert_null(ini.sections_tail);
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
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", &dummy, 0));
    cppcut_assert_null(ini.sections_head);
    cppcut_assert_null(ini.sections_tail);

    inifile_free(&ini);
}

/*!\test
 * Read a simple file containing two lines.
 */
void test_parse_one_section_with_one_entry_from_memory()
{
    static const char text[] = "[global]\nkey = value";

    struct ini_file ini;
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);
    cppcut_assert_not_null(ini.sections_tail);

    const auto *section = inifile_find_section(&ini, "global", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));

    inifile_free(&ini);
}

/*!\test
 * Read a file containing three sections, each containing four key/value pairs.
 *
 * This test is not exhaustive. It parses the file and then queries only a few
 * key/value pairs.
 */
void test_parse_from_memory()
{
    static const char text[] =
        "[section 1]\n"
        "section 1 key 1 = value 1 in section 1\n"
        "section 1 key 2 = value 2 in section 1\n"
        "section 1 key 3 = value 3 in section 1\n"
        "section 1 key 4 = value 4 in section 1\n"
        "[section 2]\n"
        "section 2 key 1 = value 1 in section 2\n"
        "section 2 key 2 = value 2 in section 2\n"
        "section 2 key 3 = value 3 in section 2\n"
        "section 2 key 4 = value 4 in section 2\n"
        "[section 3]\n"
        "section 3 key 1 = value 1 in section 3\n"
        "section 3 key 2 = value 2 in section 3\n"
        "section 3 key 3 = value 3 in section 3\n"
        "section 3 key 4 = value 4 in section 3\n"
        ;

    struct ini_file ini;
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);
    cppcut_assert_not_null(ini.sections_tail);


    const auto *section = inifile_find_section(&ini, "section 1", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "section 1 key 1", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 1 in section 1", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "section 1 key 4", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 4 in section 1", static_cast<const char *>(pair->value));


    section = inifile_find_section(&ini, "section 3", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "section 3 key 2", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 2 in section 3", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "section 3 key 4", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 4 in section 3", static_cast<const char *>(pair->value));

    inifile_free(&ini);
}

};

/*!@}*/
