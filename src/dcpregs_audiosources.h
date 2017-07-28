/*
 * Copyright (C) 2017  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_AUDIOSOURCES_H
#define DCPREGS_AUDIOSOURCES_H

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/*!
 * \addtogroup registers
 */
/*!@{*/

#ifdef __cplusplus
extern "C" {
#endif

void dcpregs_audiosources_init(void);
void dcpregs_audiosources_deinit(void);

ssize_t dcpregs_read_80_get_known_audio_sources(uint8_t *response, size_t length);
int dcpregs_write_80_get_known_audio_sources(const uint8_t *data, size_t length);

ssize_t dcpregs_read_81_current_audio_source(uint8_t *response, size_t length);
int dcpregs_write_81_current_audio_source(const uint8_t *data, size_t length);

/*!
 * Retrieve audio paths from audio path manager for first initialization.
 *
 * This function reads out the list of all audio paths and updates our internal
 * representation of audio source states.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_audiosources_fetch_audio_paths(void);

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
void dcpregs_audiosources_check_external_service_credentials(void);

/*!
 * Report availibility of an audio source as part of a usable audio path.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_audiosources_source_available(const char *source_id);

/*!
 * Report selection of audio source.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_audiosources_selected_source(const char *source_id);

/*!
 * Report update of service credentials state for given credentials category.
 */
void dcpregs_audiosources_set_have_credentials(const char *cred_category,
                                               bool have_credentials);

/*!
 * Report login status change of external media service.
 *
 * \attention
 *     Called from D-Bus thread, not main context.
 */
void dcpregs_audiosources_set_login_state(const char *cred_category,
                                          bool is_logged_in);

/*!
 * Be aware of unit test mode.
 *
 * \bug This is not the way to do it. Code must *never* be aware of unit test
 *      vs production mode. The correct way would be to implement a dummy
 *      version of #tdbusaupathManager within unit tests so that the dynamic
 *      type cast from \c GObject to #tdbusaupathManager works without any
 *      special code.
 */
void dcpregs_audiosources_set_unit_test_mode(void);

#ifdef __cplusplus
}
#endif

/*!@}*/

#endif /* !DCPREGS_AUDIOSOURCES_H */
