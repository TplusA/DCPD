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

/*!
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

/*!
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

/*!
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
    mock_messages->expect_msg_error_formatted(EINVAL, LOG_ERR,
        "Expected value after equals sign (line 2 in \"test\") (Invalid argument)");

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
        "Expected value after equals sign (line 2 in \"test\") (Invalid argument)");

    cppcut_assert_equal(0, inifile_parse_from_memory(&ini, "test", text, sizeof(text) - 8));
    cppcut_assert_not_null(ini.sections_head);

    section = inifile_find_section(&ini, "section", 0);
    cppcut_assert_not_null(section);

    pair = inifile_section_lookup_kv_pair(section, "key", 0);
    cppcut_assert_null(pair);
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

static struct ini_file ini;

void cut_setup(void)
{
    /* allow #inifile_free() to work in
     * #inifile_manipulation_tests::cut_teardown() in case of early test
     * failures */
    inifile_new(&ini);
}

void cut_teardown(void)
{
    inifile_free(&ini);
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

};

/*!@}*/
