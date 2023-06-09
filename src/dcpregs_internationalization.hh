/*
 * Copyright (C) 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_INTERNATIONALIZATION_HH
#define DCPREGS_INTERNATIONALIZATION_HH

#include <cinttypes>
#include <cstdlib>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace I18n
{

namespace DCP
{
ssize_t read_47_language_settings(uint8_t *response, size_t length);

/*!
 * Configure language and country configuration.
 *
 * The register expects four zero-terminated strings, each of which consisting
 * of either 2 or 0 characters with arbitrary capitalization. Thus, the maximum
 * total parameter size is 12 bytes. A zero-terminator for each string is
 * mandatory. Capitalization is fixed up internally the way is required for the
 * various internationalization sites.
 *
 * The first string is a non-empty alpha-2 language code as specified by ISO
 * 639-1 for the spoken language to be used by the system. The language code
 * must not be empty and must consist of exactly two letters, but other than
 * that the code is more or less used as is.
 *
 * The second string is a non-empty alpha-2 country code as specified by ISO
 * 3166-1 for the territory. This country code specifies a region-specific
 * variation of the spoken language. The code is more or less used as is.
 *
 * The third string is a language code for Airable. At the time of this
 * writing, the following language codes are supported by Airable: "de", "en",
 * "es", "fr", and "it". The use of any other codes results in behavior
 * specified by Airable. If left empty, then either the first language code is
 * used if supported by Airable, or "en" is assumed if not supported. Thus, the
 * language code passed in this parameter is used as an explicit override so
 * that any language code can be passed to Airable.
 *
 * The fourth string is a non-empty alpha-2 country code. This country code is
 * used to inform Airable about the physical location of the appliance (in case
 * GeoIP fails, used for content selection/filtering). Note that the purpose of
 * this country code is completely different from the one passed as second
 * string, which specifies a variation of the spoken language, not a physical
 * location.
 *
 * If left unconfigured, the default settings are US-English for the system
 * language, and English language and Germany for the physical location for
 * Airable. This corresponds to "en\0US\0en\0DE\0" (or "en\0US\0\0DE\0" if
 * relying on defaults).
 */
int write_47_language_settings(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_INTERNATIONALIZATION_HH */
