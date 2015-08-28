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

#include <cppcutter.h>
#include <string.h>
#include <algorithm>

#include "inifile.h"

#include "mock_messages.hh"
#include "mock_os.hh"

/*!
 * \addtogroup inifile_tests Unit tests
 * \ingroup inifile
 *
 * INI file parser and generator unit tests.
 */
/*!@{*/

namespace inifile_parser_tests
{

static MockMessages *mock_messages;
static struct ini_file ini;

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    /* allow #inifile_free() to work in #inifile_parser_tests::cut_teardown()
     * in case of early test failures */
    inifile_new(&ini);
}

void cut_teardown(void)
{
    inifile_free(&ini);

    mock_messages->check();

    mock_messages_singleton = nullptr;

    delete mock_messages;

    mock_messages = nullptr;
}

/*!\test
 * Reading an empty file works and results in empty structures.
 */
void test_parse_empty_file_from_memory()
{
    memset(&ini, 0xff, sizeof(ini));

    static const char dummy = '\0';
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", &dummy, 0));
    cppcut_assert_null(ini.sections_head);
    cppcut_assert_null(ini.sections_tail);
}

/*!\test
 * Read a simple file containing two lines.
 */
void test_parse_one_section_with_one_entry_from_memory()
{
    static const char text[] = "[global]\nkey = value";

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);
    cppcut_assert_not_null(ini.sections_tail);

    const auto *section = inifile_find_section(&ini, "global", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));
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
}

/*!\test
 * Read a file containing an assignment of nothing to some value.
 */
void test_parse_empty_value()
{
    static const char text[] =
        "[global]\n"
        "key 1 =\n"
        "key 2=\n"
        "key 3 = \n"
        "key 4 =     \n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);
    cppcut_assert_not_null(ini.sections_tail);

    const auto *section = inifile_find_section(&ini, "global", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key 1", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key 2", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key 3", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key 4", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("", static_cast<const char *>(pair->value));
}

/*!\test
 * Attempting to find non-existent keys in a section returns \c NULL pointers.
 */
void test_lookup_nonexistent_key_in_section_returns_null()
{
    static const char text[] =
        "[foo]\n"
        "key 1 = bar"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "foo", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key 2", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "key does not exist", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * Assignments outside sections are ignored.
 */
void test_parser_skips_assignments_before_first_section()
{
    static const char text[] =
        "ignore = this \n"
        "[section]\n"
        "key 1 = value 1"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 1 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key 1", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 1", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "ignore", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * Empty sections are OK.
 */
void test_parser_accepts_empty_sections()
{
    static const char text[] =
        "[empty section]\n"
        "[non-empty section]\n"
        "key = value\n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "empty section", 0);
    cppcut_assert_not_null(section);
    cppcut_assert_null(section->values_head);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);

    section = inifile_find_section(&ini, "non-empty section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));
}

/*!\test
 * Whitespace is being ignored in various places.
 */
void test_parser_ignores_insignificant_spaces()
{
    static const char text[] =
        "\n"
        "  \n"
        "     [empty section]   \n"
        "\n"
        "\t\t   \t\n"
        "[ empty section]\n"
        "key a = value a\n"
        "[empty section ]\n"
        "key b = value b\n"
        "\t\t[non-empty section]\t\t\t\n"
        "\n"
        "   \t  key 1 = value 1\n"
        "key 2 = value 2  \t    \n"
        "key 3=value 3\n"
        "\t\t\n"
        "   \n"
        " \t\t  \n"
        "\n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "empty section", 0);
    cppcut_assert_not_null(section);
    cppcut_assert_null(section->values_head);


    section = inifile_find_section(&ini, " empty section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key a", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value a", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key b", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "key 1", 0);
    cppcut_assert_null(pair);


    section = inifile_find_section(&ini, "empty section ", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key b", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value b", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key a", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "key 1", 0);
    cppcut_assert_null(pair);


    section = inifile_find_section(&ini, "non-empty section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key 1", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 1", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key 2", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 2", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key 3", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 3", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "key a", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "key b", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * In case the input file ends within a section header, that section is
 * ignored.
 */
void test_end_of_file_within_section_header_ignores_section()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "qux = qoo\n"
        "[foo"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "End of file within section header (line 4 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "qux", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("qoo", static_cast<const char *>(pair->value));

    section = inifile_find_section(&ini, "foo", 0);
    cppcut_assert_null(section);
}

/*!\test
 * In case there is a line break within a section header, that section is
 * ignored.
 */
void test_end_of_line_within_section_header_ignores_section()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "qux = qoo\n"
        "[foo\n"
        "]\n"
        "foo key 1 = foo value 1\n"
        "foo key 2 = foo value 2\n"
        "[bar]\n"
        "bar key 1 = bar value 1\n"
        "bar key 2 = bar value 2\n"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "End of line within section header (line 4 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 5 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 6 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 7 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "foo key 1", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "foo key 1", 0);
    cppcut_assert_null(pair);


    section = inifile_find_section(&ini, "foo", 0);
    cppcut_assert_null(section);


    section = inifile_find_section(&ini, "bar", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "bar key 1", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("bar value 1", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "bar key 2", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("bar value 2", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "foo key 1", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "foo key 1", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * Line numbering in error messages is not confused if there are multiple
 * parser errors.
 */
void test_line_numbers_in_error_messages_remain_accurate()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "qux = qoo\n"
        "[foo\n"
        "]\n"
        "foo key 1 = foo value 1\n"
        "[bar]\n"
        "bar key 1 = bar value 1\n"
        "[foobar\n"
        "\n"
        " \n"
        "foobar key 1 = foobar value 1\n"
        "foobar key 2 = foobar value 2\n"
        "\n"
        "  [  broken"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "End of line within section header (line 4 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 5 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 6 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "End of line within section header (line 9 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 12 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 13 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "End of file within section header (line 15 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    section = inifile_find_section(&ini, "foo", 0);
    cppcut_assert_null(section);

    section = inifile_find_section(&ini, "bar", 0);
    cppcut_assert_not_null(section);

    section = inifile_find_section(&ini, "foobar", 0);
    cppcut_assert_null(section);
}

/*!\test
 * Line gets ignored if the assignment character is missing where an assignment
 * is expected.
 */
void test_missing_assignment_character_is_detected()
{
    static const char text[] =
        "[section]\n"
        "key value\n"
        "a = b\n"
        ;

    /* EOL */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected assignment (line 2 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);

    inifile_free(&ini);

    /* EOF */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected assignment (line 2 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 8));
    cppcut_assert_not_null(ini.sections_head);

    section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * Line gets ignored if there is no value after the assignment character.
 */
void test_missing_value_after_assignment_is_detected()
{
    static const char text[] =
        "[section]\n"
        "key =\n"
        "a = b\n"
        ;

    /* EOL */
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "a", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("b", static_cast<const char *>(pair->value));

    inifile_free(&ini);

    /* EOF */
    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 8));
    cppcut_assert_not_null(ini.sections_head);

    section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
}

/*!\test
 * Line gets ignored if there is no key name in front of the assignment
 * character.
 */
void test_missing_key_name_before_assignment_is_detected()
{
    static const char text[] =
        "[section]\n"
        "= value\n"
        "a = b\n"
        ;

    /* EOL */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected key name (line 2 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);

    pair = inifile_section_lookup_kv_pair(section, "a", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("b", static_cast<const char *>(pair->value));

    inifile_free(&ini);

    /* EOF */
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected key name (line 2 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 8));
    cppcut_assert_not_null(ini.sections_head);

    section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);
}

/*!\test
 * Values may contain the assignment character.
 */
void test_second_assignment_character_is_part_of_value()
{
    static const char text[] =
        "[section]\n"
        "key = value = foo\n";

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value = foo", static_cast<const char *>(pair->value));
}

/*!\test
 * A section header with empty name is invalid and causes the parser to search
 * for the next valid section header.
 *
 * Anything betwee the empty section header and the next valid section header
 * gets ignored.
 */
void test_sections_with_empty_section_name_are_skipped()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "[]\n"
        "foo = bar\n"
        "[section 2]\n"
        "key 2 = value 2\n"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Empty section name (line 3 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 4 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));

    section = inifile_find_section(&ini, "", 0);
    cppcut_assert_null(section);

    section = inifile_find_section(&ini, "section 2", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key 2", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 2", static_cast<const char *>(pair->value));
}

/*!\test
 * A section header name may be a simple whitespace.
 */
void test_sections_with_whitespace_section_names_are_ok()
{
    static const char text[] =
        "[ ]\n"
        "foo = bar\n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, " ", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "foo", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("bar", static_cast<const char *>(pair->value));
}

/*!\test
 * Only blank characters and a newline may follow the closing bracket of a
 * section header, otherwise the header is considered invalid.
 */
void test_sections_with_junk_after_section_header_are_skipped()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "[section 2] x\n"
        "foo = bar\n"
        "[section 3]\n"
        "key 3 = value 3\n"
        ;

    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Got junk after section header (line 3 in \"test\") (Invalid argument)");
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected begin of section, got junk (line 4 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value", static_cast<const char *>(pair->value));

    section = inifile_find_section(&ini, "section 2", 0);
    cppcut_assert_null(section);

    section = inifile_find_section(&ini, "section 3", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key 3", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 3", static_cast<const char *>(pair->value));
}

/*!\test
 * Keys can have values assigned multiple times, but only the last value is
 * taken.
 */
void test_multiple_assignments_to_a_key_name_keeps_last_assignment()
{
    static const char text[] =
        "[section]\n"
        "key = value\n"
        "foo = bar\n"
        "key = value 2\n"
        "foo = foobar\n"
        "key = value 3\n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    const auto *section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    const auto *pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("value 3", static_cast<const char *>(pair->value));

    pair = inifile_section_lookup_kv_pair(section, "foo", 0);
    cppcut_assert_not_null(pair);
    cppcut_assert_equal("foobar", static_cast<const char *>(pair->value));
}

};

namespace inifile_manipulation_tests
{

static MockMessages *mock_messages;
static MockOs *mock_os;
static struct ini_file ini;

static std::vector<char> os_write_buffer;
static constexpr int expected_os_write_fd = 123;

static int write_from_buffer_callback(const void *src, size_t count, int fd)
{
    cppcut_assert_equal(expected_os_write_fd, fd);
    cppcut_assert_not_null(src);
    cppcut_assert_operator(size_t(0), <, count);

    std::copy_n(static_cast<const char *>(src), count,
                std::back_inserter<std::vector<char>>(os_write_buffer));

    return 0;
}

void cut_setup(void)
{
    mock_messages = new MockMessages;
    cppcut_assert_not_null(mock_messages);
    mock_messages->init();
    mock_messages_singleton = mock_messages;

    mock_os = new MockOs;
    cppcut_assert_not_null(mock_os);
    mock_os->init();
    mock_os_singleton = mock_os;

    os_write_buffer.clear();

    /* allow #inifile_free() to work in
     * #inifile_manipulation_tests::cut_teardown() in case of early test
     * failures */
    inifile_new(&ini);
}

void cut_teardown(void)
{
    inifile_free(&ini);

    os_write_buffer.clear();
    os_write_buffer.shrink_to_fit();

    mock_messages->check();
    mock_os->check();

    mock_messages_singleton = nullptr;
    mock_os_singleton = nullptr;

    delete mock_messages;
    delete mock_os;

    mock_messages = nullptr;
    mock_os = nullptr;
}

/*!\test
 * Initialize INI file structure in memory.
 */
void test_create_empty_file_structure()
{
    memset(&ini, 0xff, sizeof(ini));

    inifile_new(&ini);
    cppcut_assert_null(ini.sections_head);
    cppcut_assert_null(ini.sections_tail);
}

/*!\test
 * Construct an INI file containing two sections with a few assignments and a
 * third, empty section.
 */
void test_new_write_ini_file()
{
    auto *section = inifile_new_section(&ini, "First", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 1", 0, "value 1", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 2", 0, "value 2", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 3", 0, "value 3", 0));

    section = inifile_new_section(&ini, "Second", 0);
    cppcut_assert_not_null(section);

    section = inifile_new_section(&ini, "Third", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "foo", 0, "bar", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "foobar", 0, "barfoo", 0));

    mock_os->expect_os_file_new(expected_os_write_fd, "outfile.config");
    for(int i = 0; i < 3 * 3 + (3 + 0 + 2) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    cppcut_assert_equal(0, inifile_write_to_file(&ini, "outfile.config"));

    static const char expected_ini_file[] =
        "[First]\n"
        "key 1 = value 1\n"
        "key 2 = value 2\n"
        "key 3 = value 3\n"
        "[Second]\n"
        "[Third]\n"
        "foo = bar\n"
        "foobar = barfoo\n"
        ;

    cut_assert_equal_memory(expected_ini_file, sizeof(expected_ini_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * It is possible to assign empty values to keys.
 */
void test_write_empty_value_to_ini_file()
{
    auto *section = inifile_new_section(&ini, "First", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_empty_value(section, "empty", 0));

    section = inifile_new_section(&ini, "Second", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "foo", 0, "bar", 0));
    cppcut_assert_not_null(inifile_section_store_empty_value(section, "foobar", 0));

    mock_os->expect_os_file_new(expected_os_write_fd, "outfile.config");
    for(int i = 0; i < 2 * 3 + 3 + 4 + 3; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    cppcut_assert_equal(0, inifile_write_to_file(&ini, "outfile.config"));

    static const char expected_ini_file[] =
        "[First]\n"
        "empty = \n"
        "[Second]\n"
        "foo = bar\n"
        "foobar = \n"
        ;

    cut_assert_equal_memory(expected_ini_file, sizeof(expected_ini_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * Parse an INI file, change a few values, write a new INI file containing the
 * changes.
 */
void test_manipulate_value_in_file()
{
    static const char text[] =
        "[First]\n"
        "key 1-1 = value 1-1\n"
        "key 1-2 = value 1-2\n"
        "[Second]\n"
        "key 2-1 = value 2-1\n"
        "key 2-2 = value 2-2\n"
        "key 2-3 = value 2-3\n"
        "[Third]\n"
        "key 3-1 = value 3-1\n"
        "key 3-2 = value 3-2\n"
        ;

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 1));
    cppcut_assert_not_null(ini.sections_head);

    auto *section = inifile_find_section(&ini, "Second", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 2-1", 0,
                                                       "changed value", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 11-13", 0,
                                                       "new value", 0));

    section = inifile_find_section(&ini, "Third", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 3-2", 0,
                                                       "also changed", 0));

    mock_os->expect_os_file_new(expected_os_write_fd, "outfile.config");
    for(int i = 0; i < 3 * 3 + (2 + 4 + 2) * 4; ++i)
        mock_os->expect_os_write_from_buffer_callback(write_from_buffer_callback);
    mock_os->expect_os_file_close(expected_os_write_fd);

    cppcut_assert_equal(0, inifile_write_to_file(&ini, "outfile.config"));

    static const char expected_ini_file[] =
        "[First]\n"
        "key 1-1 = value 1-1\n"
        "key 1-2 = value 1-2\n"
        "[Second]\n"
        "key 2-1 = changed value\n"
        "key 2-2 = value 2-2\n"
        "key 2-3 = value 2-3\n"
        "key 11-13 = new value\n"
        "[Third]\n"
        "key 3-1 = value 3-1\n"
        "key 3-2 = also changed\n"
        ;

    cut_assert_equal_memory(expected_ini_file, sizeof(expected_ini_file) - 1,
                            os_write_buffer.data(), os_write_buffer.size());
}

/*!\test
 * In case #os_file_new() fails for whatever reason, function
 * #inifile_write_to_file() returns an error.
 */
void test_write_file_fails_if_file_cannot_be_created()
{
    cppcut_assert_not_null(inifile_new_section(&ini, "section", 0));
    mock_os->expect_os_file_new(-1, "outfile.config");
    cppcut_assert_equal(-1, inifile_write_to_file(&ini, "outfile.config"));
    cut_assert_true(os_write_buffer.empty());
}

/*!\test
 * In case #os_write_from_buffer() fails for whatever reason, function
 * #inifile_write_to_file() deletes the output file and returns an error.
 */
void test_write_file_fails_if_file_cannot_be_written()
{
    cppcut_assert_not_null(inifile_new_section(&ini, "section", 0));

    mock_os->expect_os_file_new(expected_os_write_fd, "outfile.config");
    mock_os->expect_os_write_from_buffer(-1, false, 1, expected_os_write_fd);
    mock_os->expect_os_file_close(expected_os_write_fd);
    mock_os->expect_os_file_delete("outfile.config");
    mock_messages->expect_msg_error_formatted(0, LOG_ERR,
        "Failed writing INI file \"outfile.config\", deleting partially written file");

    cppcut_assert_equal(-1, inifile_write_to_file(&ini, "outfile.config"));

    cut_assert_true(os_write_buffer.empty());
}

/*!\test
 * Removing a key from an empty section returns an error.
 */
void test_remove_key_from_empty_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cut_assert_false(inifile_section_remove_value(section, "key", 0));
}

/*!\test
 * Removing the only key results in an empty section.
 */
void test_remove_only_key_from_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key", 0, "value", 0));

    cut_assert_true(inifile_section_remove_value(section, "key", 0));
    cppcut_assert_null(section->values_head);
    cppcut_assert_null(section->values_tail);
}

/*!\test
 * Removing the first key from a section works as expected.
 */
void test_remove_existing_first_key_from_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 1", 0, "value 1", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 2", 0, "value 2", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 3", 0, "value 3", 0));

    auto *head = section->values_head;
    auto *tail = section->values_tail;

    cut_assert_true(inifile_section_remove_value(section, "key 1", 0));

    cppcut_assert_null(inifile_section_lookup_kv_pair(section, "key 1", 0));
    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 2", 0));
    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 3", 0));

    cppcut_assert_not_equal(head, section->values_head);
    cppcut_assert_equal(tail, section->values_tail);
}

/*!\test
 * Removing a key from the middle of a section works as expected.
 */
void test_remove_existing_middle_key_from_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 1", 0, "value 1", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 2", 0, "value 2", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 3", 0, "value 3", 0));

    auto *head = section->values_head;
    auto *tail = section->values_tail;

    cut_assert_true(inifile_section_remove_value(section, "key 2", 0));

    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 1", 0));
    cppcut_assert_null(inifile_section_lookup_kv_pair(section, "key 2", 0));
    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 3", 0));

    cppcut_assert_equal(head, section->values_head);
    cppcut_assert_equal(tail, section->values_tail);
}

/*!\test
 * Removing the last key from a section works as expected.
 */
void test_remove_existing_tail_key_from_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key 1", 0, "value 1", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 2", 0, "value 2", 0));
    cppcut_assert_not_null(inifile_section_store_value(section, "key 3", 0, "value 3", 0));

    auto *head = section->values_head;
    auto *tail = section->values_tail;

    cut_assert_true(inifile_section_remove_value(section, "key 3", 0));

    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 1", 0));
    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key 2", 0));
    cppcut_assert_null(inifile_section_lookup_kv_pair(section, "key 3", 0));

    cppcut_assert_equal(head, section->values_head);
    cppcut_assert_not_equal(tail, section->values_tail);
}

/*!\test
 * Removing a non-existent key from a section returns an error.
 */
void test_remove_nonexistant_key_from_section()
{
    auto *section = inifile_new_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    cppcut_assert_not_null(inifile_section_store_value(section, "key", 0, "value", 0));
    cut_assert_false(inifile_section_remove_value(section, "k", 0));
    cppcut_assert_not_null(inifile_section_lookup_kv_pair(section, "key", 0));
}

};

/*!@}*/
