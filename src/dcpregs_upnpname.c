/*
 * Copyright (C) 2016  T+A elektroakustik GmbH & Co. KG
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "dcpregs_upnpname.h"
#include "shutdown_guard.h"
#include "messages.h"

static const char key_assignment[] = "FRIENDLY_NAME_OVERRIDE=";

/*!
 * Read UPnP friendly name from configuration file.
 *
 * Note: This is not a general parser for shell variable assignments.
 */
static ssize_t read_name_from_config_file(const char *filename,
                                          char *buffer, size_t buffer_size)
{
    struct os_mapped_file_data mapped_file;

    if(os_map_file_to_memory(&mapped_file, filename) < 0)
        return -1;

    ssize_t ret = -1;

    if(mapped_file.length < (sizeof(key_assignment) - 1 + 2 + 1))
    {
        msg_error(0, LOG_ERR, "UPnP configuration file too short");
        goto exit_unmap;
    }

    const char *file = mapped_file.ptr;

    if(strncmp(file, key_assignment, sizeof(key_assignment) - 1) != 0 ||
       file[sizeof(key_assignment) - 1] != '\'' ||
       file[mapped_file.length - 2] != '\'' ||
       file[mapped_file.length - 1] != '\n')
    {
        msg_error(0, LOG_ERR, "Unexpected file content");
        goto exit_unmap;
    }

    const char *name = file + sizeof(key_assignment);
    size_t i = 0;
    const size_t end = mapped_file.length - sizeof(key_assignment) - 2;

    ret = 0;

    while(i < end && (size_t)ret < buffer_size)
    {
        const char ch = name[i];

        if(ch != '\'')
        {
            buffer[ret++] = ch;
            ++i;
        }
        else if(i < end - 4 && name[i + 1] == '\\' &&
                name[i + 2] == '\'' && name[i + 3] == '\'')
        {
            buffer[ret++] = '\'';
            i += 4;
        }
        else
        {
            msg_error(0, LOG_ERR,
                      "Unexpected end of assignment at position %zu", i);
            ret = -1;
            break;
        }
    }

exit_unmap:
    os_unmap_file(&mapped_file);

    return ret;
}

static bool is_stored_name_equal(const char *filename,
                                 const char *new_name, size_t new_name_size)
{
    char buffer[256];
    const ssize_t len =
        read_name_from_config_file(filename, buffer, sizeof(buffer));

    if(len < 0 || (size_t)len > new_name_size)
        return false;

    for(size_t i = 0; i < (size_t)len; ++i)
    {
        if(new_name[i] != buffer[i])
            return false;
    }

    /* detect and allow zero-padding */
    for(size_t i = (size_t)len; i < new_name_size; ++i)
    {
        if(new_name[i] != '\0')
            return false;
    }

    return true;
}

static size_t fill_output_buffer(char *buffer, size_t max_escaped_name_length,
                                 const char *name, size_t name_length)
{
    static const char escaped_tick[] = "'\\''";

    size_t output_size = 0;

    for(size_t i = 0; i < name_length; ++i)
    {
        const char ch = name[i];

        if(ch == '\'')
            output_size += sizeof(escaped_tick) - 1;
        else
            ++output_size;
    }

    if(output_size > max_escaped_name_length)
    {
        msg_error(0, EINVAL, "UPnP name too long");
        return 0;
    }

    char *ptr = buffer;

    memcpy(ptr, key_assignment, sizeof(key_assignment) - 1);
    ptr += sizeof(key_assignment) - 1;
    *ptr++ = '\'';

    if(output_size == name_length)
    {
        memcpy(ptr, name, name_length);
        ptr += name_length;
    }
    else
    {
        for(size_t i = 0; i < name_length; ++i)
        {
            const char ch = name[i];

            if(ch != '\'')
                *ptr++ = ch;
            else
            {
                memcpy(ptr, escaped_tick, sizeof(escaped_tick) - 1);
                ptr += sizeof(escaped_tick) - 1;
            }
        }
    }

    *ptr++ = '\'';
    *ptr++ = '\n';

    return ptr - buffer;
}

/*!
 * Write configuration file for Flagpole.
 *
 * \retval  0 Succeeded.
 * \retval  1 File system changed, but failed writing configuration.
 * \retval -1 Failed, file system unchanged.
 */
static int write_name_to_config_file(const char *filename, const char *rcpath,
                                     const char *name, size_t name_length,
                                     struct ShutdownGuard *shutdown_guard)
{
    if(shutdown_guard_is_shutting_down_unlocked(shutdown_guard))
    {
        msg_info("Not writing UPnP configuration during shutdown.");
        return -1;
    }

    char buffer[512];

    static const size_t maximum_allowed_output_size =
        sizeof(buffer) - (sizeof(key_assignment) - 1 + 2 + 1);

    const size_t bytes =
        fill_output_buffer(buffer, maximum_allowed_output_size,
                           name, name_length);

    log_assert(bytes <= sizeof(buffer));

    if(bytes == 0)
        return -1;

    int fd = os_file_new(filename);
    if(fd < 0)
        return -1;

    const int ret = (os_write_from_buffer(buffer, bytes, fd) == 0) ? 0 : 1;

    os_file_close(fd);

    if(ret != 0)
        os_file_delete(filename);

    os_sync_dir(rcpath);

    return ret;
}

static const char path_to_rcfile[] = "/var/local/etc";
static const char name_of_rcfile[] = "upnp_settings.rc";

static struct
{
    char rcfile[sizeof(path_to_rcfile) + sizeof(name_of_rcfile)];
    struct ShutdownGuard *shutdown_guard;
}
upnpname_private_data;

void dcpregs_upnpname_init(void)
{
    memcpy(upnpname_private_data.rcfile,
           path_to_rcfile, sizeof(path_to_rcfile) - 1);
    upnpname_private_data.rcfile[sizeof(path_to_rcfile) - 1] = '/';
    memcpy(upnpname_private_data.rcfile + sizeof(path_to_rcfile),
           name_of_rcfile, sizeof(name_of_rcfile));

    upnpname_private_data.shutdown_guard = shutdown_guard_alloc("upnpname");
}

void dcpregs_upnpname_deinit(void)
{
    shutdown_guard_free(&upnpname_private_data.shutdown_guard);
    memset(&upnpname_private_data, 0, sizeof(upnpname_private_data));
}

/*!
 * Read out UPnP friendly name of this device.
 *
 * \todo The name should be queried from Flagpole when it gets a proper D-Bus
 *       interface.
 *
 * \bug The hard-coded fallback name may become out of sync with Flagpole over
 *      time.
 *
 * \bug The whole approach taken by this implementation is wrong. The correct
 *      approach would be D-Bus only, not messing with configuration files and
 *      restarting systemd services. We did this to save some time.
 */
ssize_t dcpregs_read_88_upnp_friendly_name(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 88 handler %p %zu", response, length);

    ssize_t len = read_name_from_config_file(upnpname_private_data.rcfile,
                                             (char *)response, length);

    if(len >= 0)
        return len;

    static const char fallback_name[] = "T+A Streaming Board";

    len = sizeof(fallback_name) - 1;
    if((size_t)len > length)
        len = length;

    if(len > 0)
        memcpy(response, fallback_name, len);

    return len;
}

/*!
 * Write UPnP friendly name to configuration file and restart Flagpole.
 *
 * The Flagpole service is not restarted if the name is the same as already
 * configured.
 */
int dcpregs_write_88_upnp_friendly_name(const uint8_t *data, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "write 88 handler %p %zu", data, length);

    if(is_stored_name_equal(upnpname_private_data.rcfile,
                            (const char *)data, length))
    {
        msg_vinfo(MESSAGE_LEVEL_DEBUG, "UPnP name unchanged");
        return 0;
    }

    shutdown_guard_lock(upnpname_private_data.shutdown_guard);

    const int result =
        write_name_to_config_file(upnpname_private_data.rcfile, path_to_rcfile,
                                  (char *)data, length,
                                  upnpname_private_data.shutdown_guard);

    shutdown_guard_unlock(upnpname_private_data.shutdown_guard);

    if(result < 0)
        return -1;

    if(os_system("/bin/systemctl restart flagpole") != EXIT_SUCCESS)
        return 0;

    return (result != 0) ? -1 : 0;
}

void dcpregs_upnpname_prepare_for_shutdown(void)
{
    (void)shutdown_guard_down(upnpname_private_data.shutdown_guard);
}
