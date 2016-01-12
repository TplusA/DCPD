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
#include "dcpregs_networkconfig.h"
#include "dcpregs_wlansurvey.h"
#include "dcpregs_filetransfer.h"
#include "dcpregs_tcptunnel.h"
#include "dcpregs_playstream.h"
#include "dcpregs_status.h"
#include "registers_priv.h"

#define STATUS_REGISTER_READY                   ((uint8_t)0x21)
#define STATUS_REGISTER_READY_CODE_OK           ((uint8_t)0x00)
#define STATUS_REGISTER_READY_CODE_POWER_OFF    ((uint8_t)0x01)
#define STATUS_REGISTER_SYSTEM_ERROR            ((uint8_t)0x24)

const struct dcp_register_t *register_zero_for_unit_tests = NULL;

static struct
{
    uint8_t status_byte;
    uint8_t status_code;
}
misc_registers_data;

static bool update_status_register(uint8_t status, uint8_t code)
{
    if(misc_registers_data.status_byte == status &&
       misc_registers_data.status_code == code)
        return false;

    misc_registers_data.status_byte = status;
    misc_registers_data.status_code = code;

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

    response[0] = misc_registers_data.status_byte;
    response[1] = misc_registers_data.status_code;

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
    {
        /* Device status register */
        .address = 17,
        .max_data_size = 2,
        .read_handler = read_17_device_status,
    },
    {
        /* Image version */
        .address = 37,
        .max_data_size = 20,
        .read_handler = read_37_image_version,
    },
    {
        /* File transfer host control register (HCR) */
        .address = 40,
        .max_data_size = 2,
        .write_handler = dcpregs_write_40_download_control,
    },
    {
        /* File transfer status register (HCR-STATUS) */
        .address = 41,
        .max_data_size = 2,
        .read_handler = dcpregs_read_41_download_status,
    },
    {
        /* Send XMODEM block to host controller */
        .address = 44,
        .max_data_size = 3 + 128 + 2,
        .read_handler = dcpregs_read_44_xmodem_data,
    },
    {
        /* XMODEM channel from host controller */
        .address = 45,
        .max_data_size = 1,
        .write_handler = dcpregs_write_45_xmodem_command,
    },
    {
        /* Network status */
        .address = 50,
        .max_data_size = 2,
        .read_handler = dcpregs_read_50_network_status,
    },
    {
        /* MAC address */
        .address = 51,
        .max_data_size = 18,
        .read_handler = dcpregs_read_51_mac_address,
    },
    {
        /* Active IP profile (here: commit network configuration changes; see
         * also register 54) */
        .address = 53,
        .max_data_size = 1,
        .write_handler = dcpregs_write_53_active_ip_profile,
    },
    {
        /* Selected IP profile (here: start changing network configuration; see
         * also register 53) */
        .address = 54,
        .max_data_size = 1,
        .write_handler = dcpregs_write_54_selected_ip_profile,
    },
    {
        /* Enable or disable DHCP */
        .address = 55,
        .max_data_size = 1,
        .read_handler = dcpregs_read_55_dhcp_enabled,
        .write_handler = dcpregs_write_55_dhcp_enabled,
    },
    {
        /* IPv4 address */
        .address = 56,
        .max_data_size = 16,
        .read_handler = dcpregs_read_56_ipv4_address,
        .write_handler = dcpregs_write_56_ipv4_address,
    },
    {
        /* IPv4 netmask */
        .address = 57,
        .max_data_size = 16,
        .read_handler = dcpregs_read_57_ipv4_netmask,
        .write_handler = dcpregs_write_57_ipv4_netmask,
    },
    {
        /* IPv4 gateway */
        .address = 58,
        .max_data_size = 16,
        .read_handler = dcpregs_read_58_ipv4_gateway,
        .write_handler = dcpregs_write_58_ipv4_gateway,
    },
    {
        /* Primary DNS server IPv4 address */
        .address = 62,
        .max_data_size = 16,
        .read_handler = dcpregs_read_62_primary_dns,
        .write_handler = dcpregs_write_62_primary_dns,
    },
    {
        /* Secondary DNS server IPv4 address */
        .address = 63,
        .max_data_size = 16,
        .read_handler = dcpregs_read_63_secondary_dns,
        .write_handler = dcpregs_write_63_secondary_dns,
    },
    {
        /* DRC protocol */
        .address = 71,
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
    },
    {
        /* DRC command */
        .address = 72,
        .max_data_size = 3,
        .write_handler = dcpregs_write_drcp_command,
    },
    {
        /* Play stream with this title (fallback title) */
        .address = 78,
        .max_data_size = 128,
        .write_handler = dcpregs_write_78_start_play_stream_title,
    },
    {
        /* Play stream found under this URL */
        .address = 79,
        .max_data_size = 512,
        .read_handler = dcpregs_read_79_start_play_stream_url,
        .write_handler = dcpregs_write_79_start_play_stream_url,
    },
    {
        /* Wireless security setting */
        .address = 92,
        .max_data_size = 12,
        .write_handler = dcpregs_write_92_wlan_security,
        .read_handler = dcpregs_read_92_wlan_security,
    },
    {
        /* Wireless BSS/IBSS mode (infrastructure or ad-hoc) */
        .address = 93,
        .max_data_size = 8,
        .write_handler = dcpregs_write_93_ibss,
        .read_handler = dcpregs_read_93_ibss,
    },
    {
        /* Wireless SSID */
        .address = 94,
        .max_data_size = 32,
        .write_handler = dcpregs_write_94_ssid,
        .read_handler = dcpregs_read_94_ssid,
    },
    {
        /* WPA cipher type */
        .address = 101,
        .max_data_size = 8,
        .write_handler = dcpregs_write_101_wpa_cipher,
        .read_handler = dcpregs_read_101_wpa_cipher,
    },
    {
        /* WPA passphrase */
        .address = 102,
        .max_data_size = 64,
        .write_handler = dcpregs_write_102_passphrase,
        .read_handler = dcpregs_read_102_passphrase,
    },
    {
        /* WLAN site survey request */
        .address = 104,
        .max_data_size = 1,
        .write_handler = dcpregs_write_104_start_wlan_site_survey,
    },
    {
        /* WLAN site survey results */
        .address = 105,
        .read_handler_dynamic = dcpregs_read_105_wlan_site_survey_results,
    },
    {
        /* TCP tunnel control */
        .address = 119,
        .max_data_size = 3,
        .write_handler = dcpregs_write_119_tcp_tunnel_control,
    },
    {
        /* TCP tunnel: receive data from peer */
        .address = 120,
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
        .read_handler = dcpregs_read_120_tcp_tunnel_read,
    },
    {
        /* TCP tunnel: send data to peer */
        .address = 121,
        .max_data_size = DCP_PACKET_MAX_PAYLOAD_SIZE,
        .write_handler = dcpregs_write_121_tcp_tunnel_write,
    },
    {
        /* File transfer CRC mode, encryption mode, URL */
        .address = 209,
        .max_data_size = 8 + 1024,
        .write_handler = dcpregs_write_209_download_url,
    },
    {
        /* Continue playing, next stream has this title (fallback title) */
        .address = 238,
        .max_data_size = 128,
        .write_handler = dcpregs_write_238_next_stream_title,
    },
    {
        /* Continue playing, next stream found under this URL */
        .address = 239,
        .max_data_size = 512,
        .read_handler = dcpregs_read_239_next_stream_url,
        .write_handler = dcpregs_write_239_next_stream_url,
    },
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
    memset(&misc_registers_data, 0, sizeof(misc_registers_data));

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
