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

#ifndef INIFILE_H
#define INIFILE_H

#include <unistd.h>

/*!
 * \addtogroup inifile INI files
 */
/*!@{*/

struct ini_key_value_pair
{
    struct ini_key_value_pair *next;
    const char *key;
    const char *value;
};

struct ini_section
{
    struct ini_section *next;
    struct ini_key_value_pair *values_head;
    const char *name;
};

struct ini_file
{
    struct ini_section *sections_head;
};

#ifdef __cplusplus
extern "C" {
#endif

void inifile_new(struct ini_file *inifile);
int inifile_parse_from_memory(struct ini_file *inifile,
                              const char *content, size_t size);
void inifile_free(struct ini_file *inifile);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !INIFILE_H */
