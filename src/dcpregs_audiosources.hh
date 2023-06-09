/*
 * Copyright (C) 2017, 2018, 2019, 2020  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_AUDIOSOURCES_HH
#define DCPREGS_AUDIOSOURCES_HH

#include <cinttypes>
#include <cstdlib>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace AudioSources
{

void init();
void deinit();

/*!
 * Retrieve audio paths from audio path manager for first initialization.
 *
 * This function reads out the list of all audio paths and updates our internal
 * representation of audio source states.
 */
void fetch_audio_paths();

/*!
 * Retrieve availability of credentials for external media services.
 *
 * This function makes a good guess on whether or not an audio source
 * associated with the external service is usable, unless this information is
 * known from some somewhere else already.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void check_external_service_credentials();

/*!
 * Report availability of an audio source as part of a usable audio path.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void source_available(const char *source_id);

/*!
 * Report selection of audio source.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void selected_source(const char *source_id, bool is_deferred);

/*!
 * Report update of service credentials state for given credentials category.
 */
void set_have_credentials(const char *cred_category, bool have_credentials);

/*!
 * Report login status change of external media service.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void set_login_state(const char *cred_category, bool is_logged_in);

/*!
 * Be aware of unit test mode.
 *
 * \bug This is not the way to do it. Code must *never* be aware of unit test
 *      vs production mode. The correct way would be to implement a dummy
 *      version of #tdbusaupathManager within unit tests so that the dynamic
 *      type cast from \c GObject to #tdbusaupathManager works without any
 *      special code.
 */
void set_unit_test_mode();

namespace DCP
{
ssize_t read_80_get_known_audio_sources(uint8_t *response, size_t length);
int write_80_get_known_audio_sources(const uint8_t *data, size_t length);

ssize_t read_81_current_audio_source(uint8_t *response, size_t length);
int write_81_current_audio_source(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_AUDIOSOURCES_HH */
