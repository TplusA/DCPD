/*
 * Copyright (C) 2015, 2016, 2017, 2018  T+A elektroakustik GmbH & Co. KG
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

#include "registers.hh"
#include "messages.h"
#include "registers_priv.hh"
#include "configproxy.h"

#include "dcpdefs.h"
#include "dcpregs_common.h"
#include "dcpregs_drcp.h"
#include "dcpregs_protolevel.hh"
#include "dcpregs_appliance.hh"
#include "dcpregs_internationalization.hh"
#include "dcpregs_networkconfig.hh"
#include "dcpregs_wlansurvey.hh"
#include "dcpregs_upnpname.hh"
#include "dcpregs_filetransfer.hh"
#include "dcpregs_tcptunnel.hh"
#include "dcpregs_audiosources.hh"
#include "dcpregs_volume.hh"
#include "dcpregs_playstream.hh"
#include "dcpregs_mediaservices.hh"
#include "dcpregs_searchparameters.hh"
#include "dcpregs_status.hh"

#include <cstring>
#include <cinttypes>
#include <array>
#include <algorithm>

#define CURRENT_PROTOCOL_VERSION_CODE   REGISTER_MK_VERSION(1, 0, 6)

#define STATUS_REGISTER_READY                   ((uint8_t)0x21)
#define STATUS_REGISTER_READY_CODE_OK           ((uint8_t)0x00)
#define STATUS_REGISTER_READY_CODE_POWER_OFF    ((uint8_t)0x01)
#define STATUS_REGISTER_SYSTEM_ERROR            ((uint8_t)0x24)

const Regs::Register *Regs::register_zero_for_unit_tests = nullptr;

struct RegistersPrivateData
{
    Regs::ProtocolLevel configured_protocol_level;
    uint8_t status_byte;
    uint8_t status_code;
};

static RegistersPrivateData registers_private_data;

static const char max_bitrate_key[] = "@drcpd::drcpd:maximum_stream_bit_rate";

static bool update_status_register(uint8_t status, uint8_t code)
{
    if(registers_private_data.status_byte == status &&
       registers_private_data.status_code == code)
        return false;

    registers_private_data.status_byte = status;
    registers_private_data.status_code = code;

    return true;
}

void Regs::StrBoStatus::set_ready()
{
    if(update_status_register(STATUS_REGISTER_READY,
                              STATUS_REGISTER_READY_CODE_OK))
    {
        /* send device status register (17) and network status register (50) */
        const auto &config(Regs::get_data());
        config.register_changed_notification_fn(17);
        config.register_changed_notification_fn(50);
    }
}

void Regs::StrBoStatus::set_ready_to_shutdown()
{
    if(update_status_register(STATUS_REGISTER_READY,
                              STATUS_REGISTER_READY_CODE_POWER_OFF))
        Regs::get_data().register_changed_notification_fn(17);
}

void Regs::StrBoStatus::set_reboot_required()
{
    if(update_status_register(STATUS_REGISTER_SYSTEM_ERROR, 0))
        Regs::get_data().register_changed_notification_fn(17);
}

static ssize_t read_17_device_status(uint8_t *response, size_t length)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 17 handler %p %zu", response, length);
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
    msg_vinfo(MESSAGE_LEVEL_TRACE, "read 37 handler %p %zu", response, length);

    static const char osrelease_filename[] = "/etc/os-release";
    static const char key[] = "VERSION_ID=";

    struct os_mapped_file_data f;
    if(os_map_file_to_memory(&f, osrelease_filename) < 0)
        return -1;

    auto *const content = static_cast<const char *>(f.ptr);
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
                              "Truncating version ID of length %zu to %zu characters",
                              id_length, length - 1);
                else
                    msg_error(0, LOG_NOTICE,
                              "Cannot copy version ID to zero length buffer");
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
        msg_error(0, LOG_ERR, "No VERSION_ID in %s", osrelease_filename);

    return ok ? (ssize_t)length : -1;
}

static bool to_kbits(uint32_t *value)
{
    *value /= 1000U;
    return true;
}

static bool from_kbits(uint32_t *value)
{
    static const uint32_t max = UINT32_MAX / 1000U;

    if(*value <= max)
    {
        *value *= 1000U;
        return true;
    }

    msg_error(0, LOG_NOTICE, "Bit rate limit overflow (%" PRIu32 ")", *value);

    return false;
}

static ssize_t read_95_max_bitrate(uint8_t *response, size_t length)
{
    return configproxy_get_value_as_string(max_bitrate_key,
                                           (char *)response, length,
                                           to_kbits);
}

static int write_95_max_bitrate(const uint8_t *data, size_t length)
{
    length = dcpregs_trim_trailing_zero_padding(data, length);

    if(length == 0)
        return -1;

    static const char unlimited_value[] = "unlimited";

    if(length == sizeof(unlimited_value) - 1 &&
       memcmp(data, unlimited_value, sizeof(unlimited_value) - 1) == 0)
    {
        if(configproxy_set_string(nullptr, max_bitrate_key, unlimited_value))
            return 0;
    }
    else if(configproxy_set_uint32_from_string(nullptr, max_bitrate_key,
                                               (const char *)data, length,
                                               from_kbits))
        return 0;

    return -1;
}

/*!
 * List of implemented DCP registers.
 *
 * \note The entries must be sorted by address for the binary search.
 */
static const std::array<Regs::Register, 50> register_map
{
    /* Protocol level negotiation */
    Regs::Register("protocol level negotiation", 1,
                   REGISTER_MK_VERSION(1, 0, 0),
                   10 * 2 * 3,
                   Regs::DCPVersion::DCP::read_1_protocol_level,
                   Regs::DCPVersion::DCP::write_1_protocol_level),

    /* Device status register */
    Regs::Register("device status", 17,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2,
                   read_17_device_status),

    /* Appliance status register */
    Regs::Register("appliance status", 18,
                   REGISTER_MK_VERSION(1, 0, 5),
                   2,
                   Regs::Appliance::DCP::write_18_appliance_status),

    /* Appliance control register */
    Regs::Register("appliance control", 19,
                   REGISTER_MK_VERSION(1, 0, 5),
                   4,
                   Regs::Appliance::DCP::read_19_appliance_control),

    /* Image version */
    Regs::Register("StrBo version", 37,
                   REGISTER_MK_VERSION(1, 0, 0),
                   20,
                   read_37_image_version),

    /* File transfer host control register (HCR) */
    Regs::Register("file transfer control", 40,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2,
                   Regs::FileTransfer::DCP::write_40_download_control),

    /* File transfer status register (HCR-STATUS) */
    Regs::Register("file transfer status", 41,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2,
                   Regs::FileTransfer::DCP::read_41_download_status),

    /* Send XMODEM block to host controller */
    Regs::Register("XMODEM block", 44,
                   REGISTER_MK_VERSION(1, 0, 0),
                   3 + 128 + 2,
                   Regs::FileTransfer::DCP::read_44_xmodem_data),

    /* XMODEM channel from host controller */
    Regs::Register("XMODEM command", 45,
                   REGISTER_MK_VERSION(1, 0, 0),
                   1,
                   Regs::FileTransfer::DCP::write_45_xmodem_command),

    /* Language and country settings. */
    Regs::Register("language settings", 47,
                   REGISTER_MK_VERSION(1, 0, 4),
                   12,
                   Regs::I18n::DCP::read_47_language_settings,
                   Regs::I18n::DCP::write_47_language_settings),

    /* Network status */
    Regs::Register("network status", 50,
                   REGISTER_MK_VERSION(1, 0, 0),
                   3,
                   Regs::NetworkConfig::DCP::read_50_network_status),

    /* MAC address */
    Regs::Register("MAC address", 51,
                   REGISTER_MK_VERSION(1, 0, 0),
                   18,
                   Regs::NetworkConfig::DCP::read_51_mac_address),

    /* Active IP profile (here: commit network configuration changes; see
     * also register 54) */
    Regs::Register("commit network configuration", 53,
                   REGISTER_MK_VERSION(1, 0, 0),
                   1,
                   Regs::NetworkConfig::DCP::write_53_active_ip_profile),

    /* Selected IP profile (here: start changing network configuration; see
     * also register 53) */
    Regs::Register("start network configuration", 54,
                   REGISTER_MK_VERSION(1, 0, 0),
                   1,
                   Regs::NetworkConfig::DCP::write_54_selected_ip_profile),

    /* Enable or disable DHCP */
    Regs::Register("DHCP control", 55,
                   REGISTER_MK_VERSION(1, 0, 0),
                   1,
                   Regs::NetworkConfig::DCP::read_55_dhcp_enabled,
                   Regs::NetworkConfig::DCP::write_55_dhcp_enabled),

    /* IPv4 address */
    Regs::Register("IPv4 address", 56,
                   REGISTER_MK_VERSION(1, 0, 0),
                   16,
                   Regs::NetworkConfig::DCP::read_56_ipv4_address,
                   Regs::NetworkConfig::DCP::write_56_ipv4_address),

    /* IPv4 netmask */
    Regs::Register("IPv4 netmask", 57,
                   REGISTER_MK_VERSION(1, 0, 0),
                   16,
                   Regs::NetworkConfig::DCP::read_57_ipv4_netmask,
                   Regs::NetworkConfig::DCP::write_57_ipv4_netmask),

    /* IPv4 gateway */
    Regs::Register("IPv4 gateway", 58,
                   REGISTER_MK_VERSION(1, 0, 0),
                   16,
                   Regs::NetworkConfig::DCP::read_58_ipv4_gateway,
                   Regs::NetworkConfig::DCP::write_58_ipv4_gateway),

    /* Primary DNS server IPv4 address */
    Regs::Register("primary DNS", 62,
                   REGISTER_MK_VERSION(1, 0, 0),
                   16,
                   Regs::NetworkConfig::DCP::read_62_primary_dns,
                   Regs::NetworkConfig::DCP::write_62_primary_dns),

    /* Secondary DNS server IPv4 address */
    Regs::Register("secondary DNS", 63,
                   REGISTER_MK_VERSION(1, 0, 0),
                   16,
                   Regs::NetworkConfig::DCP::read_63_secondary_dns,
                   Regs::NetworkConfig::DCP::write_63_secondary_dns),

    /* Volume control */
    Regs::Register("volume control", 64,
                   REGISTER_MK_VERSION(1, 0, 4),
                   15,
                   Regs::ApplianceVolumeControl::DCP::read_64_volume_control,
                   Regs::ApplianceVolumeControl::DCP::write_64_volume_control),

    /* DRC protocol */
    Regs::Register("DRC XML", 71,
                   REGISTER_MK_VERSION(1, 0, 0),
                   DCP_PACKET_MAX_PAYLOAD_SIZE),

    /* DRC command */
    Regs::Register("DRC command", 72,
                   REGISTER_MK_VERSION(1, 0, 0),
                   3,
                   dcpregs_write_drcp_command),

    /* Seek in stream or set playback speed/direction */
    Regs::Register("seek in stream or set speed", 73,
                   REGISTER_MK_VERSION(1, 0, 3),
                   5,
                   Regs::PlayStream::DCP::write_73_seek_or_set_speed),

    /* Search parameters */
    Regs::Register("search parameters", 74,
                   REGISTER_MK_VERSION(1, 0, 0),
                   256,
                   Regs::SearchParams::DCP::write_74_search_parameters),

    /* Title of currently playing stream, if any. */
    Regs::Register("current stream title", 75,
                   REGISTER_MK_VERSION(1, 0, 0),
                   128,
                   Regs::PlayStream::DCP::read_75_current_stream_title),

    /* URL of currently playing stream, if any. */
    Regs::Register("current stream URL", 76,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2048,
                   Regs::PlayStream::DCP::read_76_current_stream_url),

    /* Play stream with this title (fallback title) */
    Regs::Register("first plain stream title", 78,
                   REGISTER_MK_VERSION(1, 0, 0),
                   128,
                   Regs::PlayStream::DCP::write_78_start_play_stream_title),

    /* Play stream found under this URL */
    Regs::Register("first plain stream URL", 79,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2048,
                   Regs::PlayStream::DCP::read_79_start_play_stream_url,
                   Regs::PlayStream::DCP::write_79_start_play_stream_url),

    /* Read out list of audio sources */
    Regs::Register("list of audio sources", 80,
                   REGISTER_MK_VERSION(1, 0, 4),
                   1024,
                   Regs::AudioSources::DCP::read_80_get_known_audio_sources,
                   Regs::AudioSources::DCP::write_80_get_known_audio_sources),

    /* Switch audio source to given ID */
    Regs::Register("switch audio source", 81,
                   REGISTER_MK_VERSION(1, 0, 4),
                   32,
                   Regs::AudioSources::DCP::read_81_current_audio_source,
                   Regs::AudioSources::DCP::write_81_current_audio_source),

    /* Set appliance ID */
    Regs::Register("appliance ID", 87,
                   REGISTER_MK_VERSION(1, 0, 1),
                   32,
                   Regs::Appliance::DCP::read_87_appliance_id,
                   Regs::Appliance::DCP::write_87_appliance_id),

    /* Set UPnP friendly name (old version) */
    Regs::Register("UPnP friendly name (OLD version)", 88,
                   REGISTER_MK_VERSION(1, 0, 1), REGISTER_MK_VERSION(1, 0, 5),
                   256,
                   Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                   Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_1),

    /* Set UPnP friendly name (new version) */
    Regs::Register("UPnP friendly name", 88,
                   REGISTER_MK_VERSION(1, 0, 6),
                   256,
                   Regs::UPnPName::DCP::read_88_upnp_friendly_name,
                   Regs::UPnPName::DCP::write_88_upnp_friendly_name__v1_0_6),

    /* Wireless security setting */
    Regs::Register("WLAN security settings", 92,
                   REGISTER_MK_VERSION(1, 0, 0),
                   12,
                   Regs::NetworkConfig::DCP::read_92_wlan_security,
                   Regs::NetworkConfig::DCP::write_92_wlan_security),

    /* Wireless BSS/IBSS mode (infrastructure or ad-hoc) */
    Regs::Register("WLAN BSS/IBSS", 93,
                   REGISTER_MK_VERSION(1, 0, 0),
                   8,
                   Regs::NetworkConfig::DCP::read_93_ibss,
                   Regs::NetworkConfig::DCP::write_93_ibss),

    /* Wireless SSID */
    Regs::Register("WLAN SSID", 94,
                   REGISTER_MK_VERSION(1, 0, 0),
                   32,
                   Regs::NetworkConfig::DCP::read_94_ssid,
                   Regs::NetworkConfig::DCP::write_94_ssid),

    /* Maximum bandwidth available for streaming */
    Regs::Register("streaming bandwidth", 95,
                   REGISTER_MK_VERSION(1, 0, 2),
                   64,
                   read_95_max_bitrate,
                   write_95_max_bitrate),

    /* WPA cipher type */
    Regs::Register("WLAN cipher type", 101,
                   REGISTER_MK_VERSION(1, 0, 0),
                   8,
                   Regs::NetworkConfig::DCP::read_101_wpa_cipher,
                   Regs::NetworkConfig::DCP::write_101_wpa_cipher),

    /* WPA passphrase */
    Regs::Register("WLAN passphrase", 102,
                   REGISTER_MK_VERSION(1, 0, 0),
                   64,
                   Regs::NetworkConfig::DCP::read_102_passphrase,
                   Regs::NetworkConfig::DCP::write_102_passphrase),

    /* WLAN site survey request */
    Regs::Register("WLAN site survey start", 104,
                   REGISTER_MK_VERSION(1, 0, 0),
                   1,
                   Regs::WLANSurvey::DCP::write_104_start_wlan_site_survey),

    /* WLAN site survey results */
    Regs::Register("WLAN site survey result", 105,
                   REGISTER_MK_VERSION(1, 0, 0),
                   Regs::WLANSurvey::DCP::read_105_wlan_site_survey_results),

    /* Query media services and set credentials */
    Regs::Register("media services", 106,
                   REGISTER_MK_VERSION(1, 0, 0),
                   Regs::MediaServices::DCP::read_106_media_service_list,
                   Regs::MediaServices::DCP::write_106_media_service_list),

    /* TCP tunnel control */
    Regs::Register("TCP tunnel control", 119,
                   REGISTER_MK_VERSION(1, 0, 0),
                   3,
                   Regs::TCPTunnel::DCP::write_119_tcp_tunnel_control),

    /* TCP tunnel: receive data from peer */
    Regs::Register("TCP tunnel data from peer", 120,
                   REGISTER_MK_VERSION(1, 0, 0),
                   DCP_PACKET_MAX_PAYLOAD_SIZE,
                   Regs::TCPTunnel::DCP::read_120_tcp_tunnel_read),

    /* TCP tunnel: send data to peer */
    Regs::Register("TCP tunnel data to peer", 121,
                   REGISTER_MK_VERSION(1, 0, 0),
                   DCP_PACKET_MAX_PAYLOAD_SIZE,
                   Regs::TCPTunnel::DCP::write_121_tcp_tunnel_write),

    /* File transfer CRC mode, encryption mode, URL */
    Regs::Register("file transfer control", 209,
                   REGISTER_MK_VERSION(1, 0, 0),
                   8 + 1024,
                   Regs::FileTransfer::DCP::write_209_download_url),

    /* Cover art hash value (cover art itself is retrieved via XMODEM) */
    Regs::Register("cover art hash", 210,
                   REGISTER_MK_VERSION(1, 0, 2),
                   16,
                   Regs::PlayStream::DCP::read_210_current_cover_art_hash),

    /* Continue playing, next stream has this title (fallback title) */
    Regs::Register("next plain stream title", 238,
                   REGISTER_MK_VERSION(1, 0, 0),
                   128,
                   Regs::PlayStream::DCP::write_238_next_stream_title),

    /* Continue playing, next stream found under this URL */
    Regs::Register("next plain stream URL", 239,
                   REGISTER_MK_VERSION(1, 0, 0),
                   2048,
                   Regs::PlayStream::DCP::read_239_next_stream_url,
                   Regs::PlayStream::DCP::write_239_next_stream_url),
};

void Regs::init(void (*register_changed_callback)(uint8_t reg_number),
                Connman::WLANTools *wlan)
{
    memset(&registers_private_data, 0, sizeof(registers_private_data));

    registers_private_data.configured_protocol_level.code =
        CURRENT_PROTOCOL_VERSION_CODE;

    auto &config(Regs::get_nonconst_data());

    config.register_changed_notification_fn = register_changed_callback;

    register_zero_for_unit_tests = nullptr;

    Regs::NetworkConfig::init();
    Regs::WLANSurvey::init(wlan);
    Regs::FileTransfer::init();
    Regs::AudioSources::init();
    Regs::PlayStream::init();
    Regs::UPnPName::init();
}

void Regs::deinit()
{
    Regs::NetworkConfig::deinit();
    Regs::WLANSurvey::deinit();
    Regs::FileTransfer::deinit();
    Regs::PlayStream::deinit();
    Regs::AudioSources::deinit();
    Regs::UPnPName::deinit();
    memset(&registers_private_data, 0, sizeof(registers_private_data));
}

bool Regs::set_protocol_level(uint8_t major, uint8_t minor, uint8_t micro)
{
    const ProtocolLevel *levels;
    const size_t num_levels = get_supported_protocol_levels(&levels);
    const uint32_t code = REGISTER_MK_VERSION(major, minor, micro);

    for(size_t i = 0; i < num_levels; ++i)
    {
        if(code >= levels[2 * i + 0].code && code <= levels[2 * i + 1].code)
        {
            registers_private_data.configured_protocol_level.code = code;
            return true;
        }
    }

    return false;
}

const Regs::ProtocolLevel Regs::get_protocol_level()
{
    return registers_private_data.configured_protocol_level;
}

size_t Regs::get_supported_protocol_levels(const ProtocolLevel **level_ranges)
{
    static const ProtocolLevel supported_level_ranges[] =
    {
#define MK_RANGE(FROM, TO) { .code = (FROM) }, { .code = (TO) }

        MK_RANGE(REGISTER_MK_VERSION(1, 0, 0), CURRENT_PROTOCOL_VERSION_CODE),

#undef MK_RANGE
    };

    *level_ranges = supported_level_ranges;

    return
        sizeof(supported_level_ranges) / sizeof(supported_level_ranges[0]) / 2;
}

void Regs::unpack_protocol_level(/* cppcheck-suppress passedByValue */
                                 const ProtocolLevel level,
                                 uint8_t *major, uint8_t *minor,
                                 uint8_t *micro)
{
    *major = (level.code >> 16) & 0xff;
    *minor = (level.code >> 8)  & 0xff;
    *micro = (level.code >> 0)  & 0xff;
}

const Regs::Register *Regs::lookup(uint8_t register_number)
{
    if(register_number == 0 && register_zero_for_unit_tests != nullptr)
        return register_zero_for_unit_tests;

    const auto it =
        std::lower_bound(
            register_map.begin(), register_map.end(),
            std::make_pair(register_number,
                           registers_private_data.configured_protocol_level),
            [] (const Regs::Register &r, const std::pair<uint8_t, ProtocolLevel> &key)
            {
                return r.address_ < key.first ||
                       (r.address_ == key.first &&
                        (r.maximum_protocol_version_.code < key.second.code ||
                         r.minimum_protocol_version_.code > key.second.code));
            });

    if(it != nullptr &&
       it->address_ == register_number &&
       registers_private_data.configured_protocol_level.code >= it->minimum_protocol_version_.code &&
       registers_private_data.configured_protocol_level.code <= it->maximum_protocol_version_.code)
        return it;

    return nullptr;
}

static Regs::PrivateData config;

const Regs::PrivateData &Regs::get_data()
{
    return config;
}

Regs::PrivateData &Regs::get_nonconst_data()
{
    return config;
}
