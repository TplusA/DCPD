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

#include "inifile.h"
#include "messages.h"

void inifile_new(struct ini_file *inifile)
{
    log_assert(inifile != NULL);

    inifile->sections_head = NULL;
}

int inifile_parse_from_memory(struct ini_file *inifile,
                              const char *content, size_t size)
{
    log_assert(inifile != NULL);
    log_assert(content != NULL);

    inifile_new(inifile);

    return 0;
}

void inifile_free(struct ini_file *inifile)
{
    log_assert(inifile != NULL);
}
