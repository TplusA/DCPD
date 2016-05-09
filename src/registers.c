/*
 * Copyright (C) 2015, 2016  T+A elektroakustik GmbH & Co. KG
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

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "registers.h"
#include "messages.h"

#include "dcpdefs.h"
#include "dcpregs_drcp.h"
#include "dcpregs_protolevel.h"
#include "dcpregs_networkconfig.h"
#include "dcpregs_wlansurvey.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_tcptunnel.h"
#include "dcpregs_playstream.h"
#include "dcpregs_mediaservices.h"
#include "dcpregs_searchparameters.h"
#include "dcpregs_status.h"
#include "registers_priv.h"

#define STATUS_REGISTER_READY                   ((uint8_t)0x21)
#define STATUS_REGISTER_READY_CODE_OK           ((uint8_t)0x00)
#define STATUS_REGISTER_READY_CODE_POWER_OFF    ((uint8_t)0x01)
#define STATUS_REGISTER_SYSTEM_ERROR            ((uint8_t)0x24)

const struct dcp_register_t *register_zero_for_unit_tests = NULL;

struct RegistersPrivateData
{
    struct RegisterProtocolLevel configured_protocol_level;
    uint8_t status_byte;
    uint8_t status_code;
};

static struct RegistersPrivateData registers_private_data;

static bool update_status_register(uint8_t status, uint8_t code)
{
    if(registers_private_data.status_byte == status &&
       registers_private_data.status_code == code)
        return false;

    registers_private_data.status_byte = status;
    registers_private_data.status_code = code;

    return true;
}

void dcpregs_status_set_ready(void)
{
    if(update_status_register(STATUS_REGISTER_READY,
                              STATUS_REGISTER_READY_CODE_OK))
    {
        /* send device status register (17) and network status register (50) */
        const struct register_configuration_t *config = registers_get_data();
        config->register_changed_notification_fn(17);
        config->register_changed_notification_fn(50);
    }
}

void dcpregs_status_set_ready_to_shutdown(void)
{
    if(update_status_register(STATUS_REGISTER_READY,
                              STATUS_REGISTER_READY_CODE_POWER_OFF))
        registers_get_data()->register_changed_notification_fn(17);
}

void dcpregs_status_set_reboot_required(void)
{
    if(update_status_register(STATUS_REGISTER_SYSTEM_ERROR, 0))
        registers_get_data()->register_changed_notification_fn(17);
}

static ssize_t read_17_device_status(uint8_t *response, size_t length)
{
    msg_info("read 17 handler %p %zu", response, length);
    log_assert(length == 2);

    response[0] = registers_private_data.status_byte;
    response[1] = registers_private_data.status_code;

    return length;
}

static size_t skip_to_eol(const char *str, size_t len, size_t offset)
{
    while(offset < len && str[offset] != '\n')
        ++offset;

    return offset;
}

static ssize_t read_37_image_version(uint8_t *response, size_t length)
{
    msg_info("read 37 handler %p %zu", response, length);

    static const char osrelease_filename[] = "/etc/os-release";
    static const char key[] = "BUILD_ID=";

    struct os_mapped_file_data f;
    if(os_map_file_to_memory(&f, osrelease_filename) < 0)
        return -1;

    const char *const content = f.ptr;
    bool ok = false;

    for(size_t i = 0; i < f.length; ++i)
    {
        const size_t remaining = f.length - i;

        if(remaining < sizeof(key) - 1)
            break;

        if(memcmp(key, content + i, sizeof(key) - 1) == 0)
        {
            i += sizeof(key) - 1;

            const size_t id_length = skip_to_eol(content, f.length, i) - i;
            const size_t bytes_to_fill =
                length > id_length + 1 ? id_length + 1 : length;

            if(length <= id_length)
            {
                if(length > 0)
                    msg_error(0, LOG_NOTICE,
                              "Truncating build ID of length %zu to %zu characters",
                              id_length, length - 1);
                else
                    msg_error(0, LOG_NOTICE,
                              "Cannot copy build ID to zero length buffer");
            }

            if(bytes_to_fill > 0)
            {
                memcpy(response, content + i, bytes_to_fill - 1);
                memset(response + bytes_to_fill - 1, 0, length - bytes_to_fill + 1);
            }
            else if(length > 0)
                memset(response, 0, length);

            ok = true;
            length = bytes_to_fill;

            break;
        }

        i = skip_to_eol(content, f.length, i);
    }

    os_unmap_file(&f);

    if(!ok)
        msg_error(0, LOG_ERR, "No BUILD_ID in %s", osrelease_filename);

    return ok ? (ssize_t)length : -1;
}

/*!
 * List of implemented DCP registers.
 *
 * \note The entries must be sorted by address for the binary search.
 */
static const struct dcp_register_t register_map[] =
{
#define REGISTER(ADDRESS, MIN_VERSION) \
    .address = (ADDRESS), \
    .minimum_protocol_version = { .code = (MIN_VERSION) }, \
    .maximum_protocol_version = { .code = REGISTER_MK_VERSION(UINT8_MAX, UINT8_MAX, UINT8_MAX) }

#define REGISTER_FOR_VERSION(ADDRESS, MIN_VERSION, MAX_VERSION) \
    .address = (ADDRESS), \
    .minimum_protocol_version = (MIN_VERSION), \
    .maximum_protocol_version = (MAX_VERSION)

    {
        /* Protocol level negotiation */
        REGISTER(1, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 10 * 2 * 3,
        .read_handler = dcpregs_read_1_protocol_level,
        .write_handler = dcpregs_write_1_protocol_level,
    },
    {
        /* Device status register */
        REGISTER(17, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 2,
        .read_handler = read_17_device_status,
    },
    {
        /* Image version */
        REGISTER(37, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 20,
        .read_handler = read_37_image_version,
    },
    {
        /* File transfer host control register (HCR) */
        REGISTER(40, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 2,
        .write_handler = dcpregs_write_40_download_control,
    },
    {
        /* File transfer status register (HCR-STATUS) */
        REGISTER(41, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 2,
        .read_handler = dcpregs_read_41_download_status,
    },
    {
        /* Send XMODEM block to host controller */
        REGISTER(44, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 3 + 128 + 2,
        .read_handler = dcpregs_read_44_xmodem_data,
    },
    {
        /* XMODEM channel from host controller */
        REGISTER(45, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1,
        .write_handler = dcpregs_write_45_xmodem_command,
    },
    {
        /* Network status */
        REGISTER(50, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 2,
        .read_handler = dcpregs_read_50_network_status,
    },
    {
        /* MAC address */
        REGISTER(51, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 18,
        .read_handler = dcpregs_read_51_mac_address,
    },
    {
        /* Active IP profile (here: commit network configuration changes; see
         * also register 54) */
        REGISTER(53, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1,
        .write_handler = dcpregs_write_53_active_ip_profile,
    },
    {
        /* Selected IP profile (here: start changing network configuration; see
         * also register 53) */
        REGISTER(54, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1,
        .write_handler = dcpregs_write_54_selected_ip_profile,
    },
    {
        /* Enable or disable DHCP */
        REGISTER(55, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1,
        .read_handler = dcpregs_read_55_dhcp_enabled,
        .write_handler = dcpregs_write_55_dhcp_enabled,
    },
    {
        /* IPv4 address */
        REGISTER(56, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 16,
        .read_handler = dcpregs_read_56_ipv4_address,
        .write_handler = dcpregs_write_56_ipv4_address,
    },
    {
        /* IPv4 netmask */
        REGISTER(57, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 16,
        .read_handler = dcpregs_read_57_ipv4_netmask,
        .write_handler = dcpregs_write_57_ipv4_netmask,
    },
    {
        /* IPv4 gateway */
        REGISTER(58, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 16,
        .read_handler = dcpregs_read_58_ipv4_gateway,
        .write_handler = dcpregs_write_58_ipv4_gateway,
    },
    {
        /* Primary DNS server IPv4 address */
        REGISTER(62, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 16,
        .read_handler = dcpregs_read_62_primary_dns,
        .write_handler = dcpregs_write_62_primary_dns,
    },
    {
        /* Secondary DNS server IPv4 address */
        REGISTER(63, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 16,
        .read_handler = dcpregs_read_63_secondary_dns,
        .write_handler = dcpregs_write_63_secondary_dns,
    },
    {
        /* DRC protocol */
        REGISTER(71, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
    },
    {
        /* DRC command */
        REGISTER(72, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 3,
        .write_handler = dcpregs_write_drcp_command,
    },
    {
        /* Search parameters */
        REGISTER(74, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 256,
        .write_handler = dcpregs_write_74_search_parameters,
    },
    {
        /* Title of currently playing stream, if any. */
        REGISTER(75, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 128,
        .read_handler = dcpregs_read_75_current_stream_title,
    },
    {
        /* URL of currently playing stream, if any. */
        REGISTER(76, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1024,
        .read_handler = dcpregs_read_76_current_stream_url,
    },
    {
        /* Play stream with this title (fallback title) */
        REGISTER(78, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 128,
        .write_handler = dcpregs_write_78_start_play_stream_title,
    },
    {
        /* Play stream found under this URL */
        REGISTER(79, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1024,
        .read_handler = dcpregs_read_79_start_play_stream_url,
        .write_handler = dcpregs_write_79_start_play_stream_url,
    },
    {
        /* Wireless security setting */
        REGISTER(92, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 12,
        .write_handler = dcpregs_write_92_wlan_security,
        .read_handler = dcpregs_read_92_wlan_security,
    },
    {
        /* Wireless BSS/IBSS mode (infrastructure or ad-hoc) */
        REGISTER(93, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 8,
        .write_handler = dcpregs_write_93_ibss,
        .read_handler = dcpregs_read_93_ibss,
    },
    {
        /* Wireless SSID */
        REGISTER(94, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 32,
        .write_handler = dcpregs_write_94_ssid,
        .read_handler = dcpregs_read_94_ssid,
    },
    {
        /* WPA cipher type */
        REGISTER(101, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 8,
        .write_handler = dcpregs_write_101_wpa_cipher,
        .read_handler = dcpregs_read_101_wpa_cipher,
    },
    {
        /* WPA passphrase */
        REGISTER(102, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 64,
        .write_handler = dcpregs_write_102_passphrase,
        .read_handler = dcpregs_read_102_passphrase,
    },
    {
        /* WLAN site survey request */
        REGISTER(104, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1,
        .write_handler = dcpregs_write_104_start_wlan_site_survey,
    },
    {
        /* WLAN site survey results */
        REGISTER(105, REGISTER_MK_VERSION(1, 0, 0)),
        .read_handler_dynamic = dcpregs_read_105_wlan_site_survey_results,
    },
    {
        /* Query media services and set credentials */
        REGISTER(106, REGISTER_MK_VERSION(1, 0, 0)),
        .read_handler_dynamic = dcpregs_read_106_media_service_list,
        .write_handler = dcpregs_write_106_media_service_list,
    },
    {
        /* TCP tunnel control */
        REGISTER(119, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 3,
        .write_handler = dcpregs_write_119_tcp_tunnel_control,
    },
    {
        /* TCP tunnel: receive data from peer */
        REGISTER(120, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
        .read_handler = dcpregs_read_120_tcp_tunnel_read,
    },
    {
        /* TCP tunnel: send data to peer */
        REGISTER(121, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
        .write_handler = dcpregs_write_121_tcp_tunnel_write,
    },
    {
        /* File transfer CRC mode, encryption mode, URL */
        REGISTER(209, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 8 + 1024,
        .write_handler = dcpregs_write_209_download_url,
    },
    {
        /* Continue playing, next stream has this title (fallback title) */
        REGISTER(238, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 128,
        .write_handler = dcpregs_write_238_next_stream_title,
    },
    {
        /* Continue playing, next stream found under this URL */
        REGISTER(239, REGISTER_MK_VERSION(1, 0, 0)),
        .max_data_size = 1024,
        .read_handler = dcpregs_read_239_next_stream_url,
        .write_handler = dcpregs_write_239_next_stream_url,
    },

#undef REGISTER
#undef REGISTER_FOR_VERSION
};

static int compare_register_address(const void *a, const void *b)
{
    return
        (int)((const struct dcp_register_t *)a)->address -
        (int)((const struct dcp_register_t *)b)->address;
}

static const char *check_mac_address(const char *mac_address,
                                     size_t required_length, bool is_wired)
{
    if(mac_address == NULL ||
       strlen(mac_address) != required_length)
    {
        /* locally administered address, invalid in the wild */
        return is_wired ? "02:00:00:00:00:00" : "03:00:00:00:00:00";
    }
    else
        return mac_address;
}

static void copy_mac_address(char *dest, size_t dest_size, const char *src)
{
    strncpy(dest, src, dest_size);
    dest[dest_size - 1] = '\0';
}

void register_init(const char *ethernet_mac_address,
                   const char *wlan_mac_address,
                   const char *connman_config_path,
                   void (*register_changed_callback)(uint8_t reg_number))
{
    memset(&registers_private_data, 0, sizeof(registers_private_data));

    registers_private_data.configured_protocol_level.code =
        REGISTER_MK_VERSION(1, 0, 0);

    struct register_configuration_t *config = registers_get_nonconst_data();
    struct register_network_interface_t *iface_data;
    const char *temp;

    iface_data = &config->builtin_ethernet_interface;
    iface_data->is_builtin = true;
    iface_data->is_wired = true;
    temp = check_mac_address(ethernet_mac_address,
                             sizeof(iface_data->mac_address_string) - 1,
                             iface_data->is_wired);
    copy_mac_address(iface_data->mac_address_string,
                     sizeof(iface_data->mac_address_string), temp);

    iface_data = &config->builtin_wlan_interface;
    iface_data->is_builtin = true;
    iface_data->is_wired = false;
    temp = check_mac_address(wlan_mac_address,
                             sizeof(iface_data->mac_address_string) - 1,
                             iface_data->is_wired);
    copy_mac_address(iface_data->mac_address_string,
                     sizeof(iface_data->mac_address_string), temp);

    config->active_interface = NULL;
    config->connman_config_path = connman_config_path;
    config->register_changed_notification_fn = register_changed_callback;

    register_zero_for_unit_tests = NULL;

    dcpregs_networkconfig_init();
    dcpregs_wlansurvey_init();
    dcpregs_filetransfer_init();
}

void register_deinit(void)
{
    dcpregs_networkconfig_deinit();
    dcpregs_wlansurvey_deinit();
    dcpregs_filetransfer_deinit();
}

const struct RegisterProtocolLevel *register_get_protocol_level(void)
{
    static const struct RegisterProtocolLevel level =
    {
        .code = REGISTER_MK_VERSION(1, 0, 0),
    };

    return &level;
}

size_t register_get_supported_protocol_levels(const struct RegisterProtocolLevel **level_ranges)
{
    static const struct RegisterProtocolLevel supported_level_ranges[] =
    {
#define MK_RANGE(FROM, TO) { .code = (FROM) }, { .code = (TO) }

        MK_RANGE(REGISTER_MK_VERSION(1, 0, 0), REGISTER_MK_VERSION(1, 0, 0)),

#undef MK_RANGE
    };

    *level_ranges = supported_level_ranges;

    return
        sizeof(supported_level_ranges) / sizeof(supported_level_ranges[0]) / 2;
}

void register_unpack_protocol_level(const struct RegisterProtocolLevel level,
                                    uint8_t *major, uint8_t *minor,
                                    uint8_t *micro)
{
    *major = (level.code >> 16) & 0xff;
    *minor = (level.code >> 8)  & 0xff;
    *micro = (level.code >> 0)  & 0xff;
}

const struct dcp_register_t *register_lookup(uint8_t register_number)
{
    if(register_number == 0 && register_zero_for_unit_tests != NULL)
        return register_zero_for_unit_tests;

    static struct dcp_register_t key;

    key.address = register_number;

    return bsearch(&key, register_map,
                   sizeof(register_map) / sizeof(register_map[0]),
                   sizeof(register_map[0]), compare_register_address);
}

bool register_is_static_size(const struct dcp_register_t *reg)
{
    log_assert(reg != NULL);
    return reg->max_data_size > 0;
}

static struct register_configuration_t config;

const struct register_configuration_t *registers_get_data(void)
{
    return &config;
}

struct register_configuration_t *registers_get_nonconst_data(void)
{
    return &config;
}
