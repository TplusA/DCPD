/*
 * Copyright (C) 2016, 2017, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include "dbus_handlers_connman_agent.hh"
#include "connman_agent.h"
#include "networkprefs.h"
#include "gvariantwrapper.hh"
#include "messages.h"

#include <array>
#include <algorithm>
#include <iterator>
#include <cstring>

/*
 * Use this when generating errors in Connman agent error domain (for GLib).
 */
#define NET_CONNMAN_AGENT_ERROR (net_connman_agent_error_quark())

/*
 * Error codes for Connman agent domain (for GLib).
 */
enum NetConnmanAgentError
{
    NET_CONNMAN_AGENT_ERROR_CANCELED,
    NET_CONNMAN_AGENT_ERROR_REJECTED,
    NET_CONNMAN_AGENT_ERROR_RETRY,
    NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER,
    NET_CONNMAN_AGENT_N_ERRORS,
};

/*
 * Error strings for error codes in Connman agent error domain (for GLib).
 */
static const GDBusErrorEntry net_connman_agent_error_entries[] =
{
    { NET_CONNMAN_AGENT_ERROR_CANCELED,       "net.connman.Agent.Error.Canceled" },
    { NET_CONNMAN_AGENT_ERROR_REJECTED,       "net.connman.Agent.Error.Rejected" },
    { NET_CONNMAN_AGENT_ERROR_RETRY,          "net.connman.Agent.Error.Retry" },
    { NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER, "net.connman.Agent.Error.LaunchBrowser" },
};

G_STATIC_ASSERT(G_N_ELEMENTS(net_connman_agent_error_entries) == NET_CONNMAN_AGENT_N_ERRORS);

/*
 * Connman agent error domain (for GLib).
 */
static GQuark net_connman_agent_error_quark(void)
{
    static volatile gsize quark_volatile = 0;
    g_dbus_error_register_error_domain("net-connman-agent-error-quark",
                                       &quark_volatile,
                                       net_connman_agent_error_entries,
                                       G_N_ELEMENTS(net_connman_agent_error_entries));
    return (GQuark)quark_volatile;
}

struct AgentData
{
    bool is_wps_mode;
};

static struct AgentData global_agent_data;

template <typename T, size_t N>
static T string_to_enum_id(const std::array<const std::string, N> &table,
                           const char *string, const T fallback)
{
    const auto it =
        std::find_if(std::next(table.begin()), table.end(),
            [&string] (const std::string &id) { return id == string; });

    return it != table.end() ? T(std::distance(table.begin(), it)) : fallback;
}

enum class RequestID
{
    /*! Any request not understood by the parser is mapped to this ID */
    UNKNOWN,

    /*! Need name of hidden network */
    NAME,

    /*! Need SSID of hidden network as an alternative to #RequestID::NAME */
    SSID,

    /*! Username for EAP authentication */
    IDENTITY,

    /*! Passphrase for WEP, PSK, etc. */
    PASSPHRASE,

    /*! Passphrase that was tried, but failed (passphrase changed or wrong) */
    PREVIOUS_PASSPHRASE,

    /*! Request use of WPS */
    WPS_PIN,

    /*! Username for WISPr authentication */
    USERNAME,

    /*! Password for WISPr authentication */
    PASSWORD,

    /*! Stable name for last ID */
    LAST_REQUEST_ID = PASSWORD,
};

enum class RequestRequirement
{
    /*! Special ID to express that there was no request for a #RequestID */
    NOT_REQUESTED,

    /*! Answer to request is mandatory, or the request must fail */
    MANDATORY,

    /*! Answer to request is optional, information not required for success */
    OPTIONAL,

    /*! Requested field is an alternative to another field */
    ALTERNATE,

    /*! Field contains information and can be safely ignored */
    INFORMATIONAL,

    /*! Stable name for last ID */
    LAST_REQUEST_REQUIREMENT = INFORMATIONAL,
};

static const std::array<const std::string, size_t(RequestID::LAST_REQUEST_ID) + 1> request_string_ids
{
    "*UNKNOWN*",
    "Name",
    "SSID",
    "Identity",
    "Passphrase",
    "PreviousPassphrase",
    "WPS",
    "Username",
    "Password",
};

static RequestID string_to_request_id(const char *string)
{
    return string_to_enum_id(request_string_ids, string, RequestID::UNKNOWN);
}

static const std::string &request_id_to_string(const RequestID id)
{
    return request_string_ids[size_t(id)];
}

static RequestRequirement string_to_request_requirement(const char *string)
{
    static const std::array<const std::string, size_t(RequestRequirement::LAST_REQUEST_REQUIREMENT) + 1> string_ids
    {
        "*UNKNOWN*",
        "mandatory",
        "optional",
        "alternate",
        "informational",
    };

    return string_to_enum_id(string_ids, string, RequestRequirement::NOT_REQUESTED);
}

class Request
{
  public:
    RequestRequirement requirement;
    uint32_t alternates;
    GVariantWrapper variant;
    bool is_answered;

    Request(const Request &) = delete;
    Request(Request &&) = default;
    Request &operator=(const Request &) = delete;
    Request &operator=(Request &&) = default;

    explicit Request():
        requirement(RequestRequirement::NOT_REQUESTED),
        alternates(0),
        is_answered(false)
    {}
};

using AllRequests = std::array<Request, size_t(RequestID::LAST_REQUEST_ID) + 1>;

static bool send_error_if_possible(GDBusMethodInvocation *invocation,
                                   const char *error_message)
{
    if(error_message == nullptr)
        return false;

    msg_vinfo(MESSAGE_LEVEL_DEBUG,
              "Error message for ConnMan: \"%s\"", error_message);

    g_dbus_method_invocation_return_error_literal(invocation,
                                                  NET_CONNMAN_AGENT_ERROR,
                                                  NET_CONNMAN_AGENT_ERROR_CANCELED,
                                                  error_message);

    return true;
}

static void enter_agent_handler(GDBusMethodInvocation *invocation)
{
    static const char iface_name[] = "net.connman.Agent";

    msg_vinfo(MESSAGE_LEVEL_TRACE, "%s method invocation from '%s': %s",
              iface_name, g_dbus_method_invocation_get_sender(invocation),
              g_dbus_method_invocation_get_method_name(invocation));
}

bool connman_agent_set_wps_mode(bool is_wps_mode)
{
    if(global_agent_data.is_wps_mode == is_wps_mode)
        return false;

    msg_info("Set agent %s mode", is_wps_mode ? "WPS" : "normal");
    global_agent_data.is_wps_mode = is_wps_mode;

    return true;
}

gboolean dbusmethod_connman_agent_release(tdbusconnmanAgent *object,
                                          GDBusMethodInvocation *invocation,
                                          void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_release(object, invocation);

    return TRUE;
}

static const char *get_service_basename(const char *full_service_name,
                                        size_t &tech_length)
{
    const char *const before_service = strrchr(full_service_name, '/');

    if(before_service == nullptr)
        return nullptr;

    const char *const service = &before_service[1];
    const char *const after_tech = strchr(service, '_');

    if(after_tech == nullptr)
        return nullptr;

    tech_length = after_tech - service;

    return tech_length > 0 ? service : nullptr;
}

static const char *delete_service_configuration(const char *full_service_name)
{
    size_t tech_length;
    const char *const service = get_service_basename(full_service_name,
                                                     tech_length);

    if(service == nullptr)
        return "Malformed service name, cannot delete";

    const enum NetworkPrefsTechnology tech =
        (tech_length == 8 && memcmp(service, "ethernet", tech_length) == 0
         ? NWPREFSTECH_ETHERNET
         : (tech_length == 4 && memcmp(service, "wifi", tech_length) == 0
            ? NWPREFSTECH_WLAN
            : NWPREFSTECH_UNKNOWN));

    if(tech == NWPREFSTECH_UNKNOWN)
        return "Technology unknown, cannot delete";

    struct network_prefs *np;
    struct network_prefs_handle *prefsfile = network_prefs_open_rw(&np, &np);

    if(prefsfile == nullptr)
        return "Failed reading network preferences, cannot delete service";

    const bool succeeded =
        network_prefs_remove_prefs(prefsfile, tech) &&
        network_prefs_write_to_file(prefsfile) == 0;

    network_prefs_close(prefsfile);

    return succeeded ? nullptr : "Failed removing service from preferences";
}

gboolean dbusmethod_connman_agent_report_error(tdbusconnmanAgent *object,
                                               GDBusMethodInvocation *invocation,
                                               const gchar *arg_service,
                                               const gchar *arg_error,
                                               void *user_data)
{
    enter_agent_handler(invocation);

    msg_error(0, LOG_ERR, "Agent error for service %s: %s", arg_service, arg_error);

    if(strcmp(arg_error, "invalid-key") == 0)
    {
        const char *error_message = delete_service_configuration(arg_service);

        if(error_message != nullptr)
            msg_error(0, LOG_NOTICE, "Error deleting configuration for %s: %s",
                      arg_service, error_message);
    }

    tdbus_connman_agent_complete_report_error(object, invocation);

    return TRUE;
}

gboolean dbusmethod_connman_agent_report_peer_error(tdbusconnmanAgent *object,
                                                    GDBusMethodInvocation *invocation,
                                                    const gchar *arg_peer,
                                                    const gchar *arg_error,
                                                    void *user_data)
{
    enter_agent_handler(invocation);

    msg_error(0, LOG_ERR, "Agent error for peer %s: %s", arg_peer, arg_error);
    tdbus_connman_agent_complete_report_peer_error(object, invocation);

    return TRUE;
}

gboolean dbusmethod_connman_agent_request_browser(tdbusconnmanAgent *object,
                                                  GDBusMethodInvocation *invocation,
                                                  const gchar *arg_service,
                                                  const gchar *arg_url,
                                                  void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    send_error_if_possible(invocation, "We do not have any browser");

    return TRUE;
}

static void unref_collected_requests(AllRequests &requests)
{
    for(auto &req : requests)
        req.variant = GVariantWrapper();
}

static const char *fill_in_request_requirement(Request &request,
                                               GVariant *value)
{
    if(request.requirement != RequestRequirement::NOT_REQUESTED)
        return "Duplicate request requirement";

    request.requirement =
        string_to_request_requirement(g_variant_get_string(value, nullptr));

    if(request.requirement == RequestRequirement::NOT_REQUESTED)
        return "Unknown request requirement";

    return nullptr;
}

static const char *fill_in_alternates(Request &request, GVariant *value)
{
    if(request.alternates != 0)
        return "Duplicate request alternates specification";

    GVariantIter alternates_iter;
    g_variant_iter_init(&alternates_iter, value);

    const gchar *alternate;

    while(g_variant_iter_next(&alternates_iter, "&s", &alternate))
    {
        const RequestID request_id = string_to_request_id(alternate);

        if(request_id == RequestID::UNKNOWN)
            return "Unknown request alternate";

        const uint32_t mask = (1U << (uint32_t(request_id) - 1));

        if((request.alternates & mask) != 0)
            return "Duplicate request alternate field";

        request.alternates |= mask;
    }

    if(request.alternates == 0)
        return "Empty request alternates specification";

    return nullptr;
}

static const char *collect_requests(AllRequests &requests, GVariant *request)
{
    GVariantIter request_iter;
    g_variant_iter_init(&request_iter, request);

    const char *return_string = nullptr;

    const gchar *request_key;
    GVariant *request_details_variant;

    while(return_string == nullptr &&
          g_variant_iter_next(&request_iter, "{&sv}",
                              &request_key, &request_details_variant))
    {
        GVariantWrapper request_details(request_details_variant, GVariantWrapper::Transfer::JUST_MOVE);
        const RequestID request_id = string_to_request_id(request_key);

        if(request_id == RequestID::UNKNOWN)
        {
            return_string = "Unknown request";
            continue;
        }

        auto &req(requests[size_t(request_id)]);

        if(req.variant != nullptr)
        {
            return_string = "Duplicate request";
            continue;
        }

        GVariantIter detail_iter;
        g_variant_iter_init(&detail_iter, GVariantWrapper::get(request_details));

        const gchar *detail_key;
        GVariant *detail_value;

        while(return_string == nullptr &&
              g_variant_iter_next(&detail_iter, "{&sv}", &detail_key, &detail_value))
        {
            if(strcmp(detail_key, "Requirement") == 0)
                return_string = fill_in_request_requirement(req, detail_value);
            else if(strcmp(detail_key, "Alternates") == 0)
                return_string = fill_in_alternates(req, detail_value);

            g_variant_unref(detail_value);
        }

        if(req.requirement != RequestRequirement::NOT_REQUESTED)
            req.variant = request_details;
        else if(return_string == nullptr)
            return_string = "Missing request requirement";
    }

    return return_string;
}

static const char *wps_get_passphrase(void)
{
    /* maybe in a distant future we'll support preset passphrases for WPS */
    return nullptr;
}

static const char *wps_get_pin(void)
{
    /* empty string means push-button method */
    return "";
}

static bool insert_answer(GVariantBuilder *result_builder,
                          Request &request, RequestID request_id,
                          const struct network_prefs *preferences)
{
    /* must match #RequestID enumeration */
    static const std::array<const char *(* const)(const struct network_prefs *),
                            size_t(RequestID::LAST_REQUEST_ID) + 1> prefgetters
    {
        nullptr,
        network_prefs_get_name,
        network_prefs_get_ssid,
        nullptr,
        network_prefs_get_passphrase,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
    };

    /* must match #RequestID enumeration */
    static const std::array<const char *(*const)(), size_t(RequestID::LAST_REQUEST_ID) + 1> wpsgetters
    {
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        wps_get_passphrase,
        nullptr,
        wps_get_pin,
        nullptr,
        nullptr,
    };

    log_assert(!request.is_answered);

    if((preferences != nullptr && prefgetters[size_t(request_id)] == nullptr) ||
       (preferences == nullptr && wpsgetters[size_t(request_id)] == nullptr))
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "ConnMan request %s not supported",
                  request_id_to_string(request_id).c_str());
        return false;
    }

    const char *const value = preferences != nullptr
        ? prefgetters[size_t(request_id)](preferences)
        : wpsgetters[size_t(request_id)]();

    if(value == nullptr)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Have no answer for ConnMan request %s",
                  request_id_to_string(request_id).c_str());
        return false;
    }

    g_variant_builder_add(result_builder, "{sv}",
                          request_id_to_string(request_id).c_str(),
                          g_variant_new_string(value));
    request.is_answered = true;

    return true;
}

static bool insert_alternate_answer(GVariantBuilder *result_builder,
                                    AllRequests &requests,
                                    RequestID related_id,
                                    const struct network_prefs *preferences)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "FIND ALTERNATE answer for unanswered request %s",
              request_id_to_string(related_id).c_str());

    if(requests[size_t(related_id)].alternates != 0)
    {
        auto alternate_id = RequestID::UNKNOWN;

        for(uint32_t alternates = requests[size_t(related_id)].alternates;
            alternates != 0;
            alternates >>= 1)
        {
            alternate_id = RequestID(size_t(alternate_id) + 1);

            if((alternates & 1U) == 0)
                continue;

            log_assert(alternate_id <= RequestID::LAST_REQUEST_ID);

            if(insert_answer(result_builder, requests[size_t(alternate_id)],
                             alternate_id, preferences))
                return true;
            else
                return insert_alternate_answer(result_builder, requests,
                                               alternate_id, preferences);
        }
    }

    msg_vinfo(MESSAGE_LEVEL_TRACE, "No alternate for %s",
              request_id_to_string(related_id).c_str());

    return false;
}

static void wipe_out_alternates(AllRequests &requests, RequestID related_id)
{
    uint32_t alternates = requests[size_t(related_id)].alternates;

    msg_vinfo(MESSAGE_LEVEL_TRACE, "WIPE OUT alternates 0x%08x for %s",
              alternates, request_id_to_string(related_id).c_str());

    if(alternates == 0)
        return;

    requests[size_t(related_id)].alternates = 0;

    auto alternate_id = RequestID::UNKNOWN;

    for(/* nothing */; alternates != 0; alternates >>= 1)
    {
        alternate_id = RequestID(size_t(alternate_id) + 1);

        if((alternates & 1U) == 0)
            continue;

        log_assert(alternate_id <= RequestID::LAST_REQUEST_ID);

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Wipe out alternate %s for processed %s",
                  request_id_to_string(alternate_id).c_str(),
                  request_id_to_string(related_id).c_str());

        requests[size_t(alternate_id)].requirement = RequestRequirement::NOT_REQUESTED;
        wipe_out_alternates(requests, alternate_id);
    }
}

static const char *
find_preferences_for_service(struct network_prefs_handle **prefsfile,
                             const struct network_prefs **preferences,
                             const char *full_service_name)
{
    *preferences = nullptr;

    size_t tech_length;
    const char *const service = get_service_basename(full_service_name,
                                                     tech_length);

    if(service == nullptr)
    {
        *prefsfile = nullptr;
        return "Malformed service name";
    }

    const struct network_prefs *dummy;
    const struct network_prefs *prefs;

    if(tech_length == 8 && memcmp(service, "ethernet", tech_length) == 0)
        *prefsfile = network_prefs_open_ro(&prefs, &dummy);
    else if(tech_length == 4 && memcmp(service, "wifi", tech_length) == 0)
        *prefsfile = network_prefs_open_ro(&dummy, &prefs);
    else
    {
        *prefsfile = nullptr;
        return "Technology unknown";
    }

    if(*prefsfile == nullptr)
        return "Failed reading network preferences";

    if(prefs == nullptr)
    {
        network_prefs_close(*prefsfile);
        *prefsfile = nullptr;
        return "Network preferences not found for service name";
    }

    char buffer[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    memcpy(buffer, service, tech_length);
    buffer[tech_length] = '\0';

    if(network_prefs_generate_service_name(prefs, buffer, sizeof(buffer), true) == 0)
    {
        network_prefs_close(*prefsfile);
        *prefsfile = nullptr;
        return "Network preferences incomplete";
    }

    *preferences = prefs;

    return nullptr;
}

gboolean dbusmethod_connman_agent_request_input(tdbusconnmanAgent *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *arg_service,
                                                GVariant *arg_fields,
                                                void *user_data)
{
    enter_agent_handler(invocation);

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Got request for service \"%s\"", arg_service);

    struct network_prefs_handle *prefsfile = nullptr;
    const struct network_prefs *preferences = nullptr;

    const char *error_message = global_agent_data.is_wps_mode
        ? nullptr
        : find_preferences_for_service(&prefsfile, &preferences, arg_service);

    if(send_error_if_possible(invocation, error_message))
        return TRUE;

    AllRequests requests;

    error_message = collect_requests(requests, arg_fields);

    if(send_error_if_possible(invocation, error_message))
    {
        unref_collected_requests(requests);

        if(prefsfile != nullptr)
            network_prefs_close(prefsfile);

        return TRUE;
    }

    GVariantBuilder result_builder;
    g_variant_builder_init(&result_builder, G_VARIANT_TYPE ("a{sv}"));

    /* fill in the mandatory requests first, fall back to alternate requests if
     * necessary, fail if not possible */
    for(size_t i = 0;
        error_message == nullptr && i <= size_t(RequestID::LAST_REQUEST_ID);
        ++i)
    {
        auto &request = requests[i];
        auto request_id = RequestID(i);

        switch(request.requirement)
        {
          case RequestRequirement::NOT_REQUESTED:
          case RequestRequirement::ALTERNATE:
          case RequestRequirement::INFORMATIONAL:
            continue;

          case RequestRequirement::MANDATORY:
          case RequestRequirement::OPTIONAL:
            if(!insert_answer(&result_builder, request, request_id, preferences) &&
               !insert_alternate_answer(&result_builder, requests, request_id, preferences))
            {
                if(request.requirement == RequestRequirement::MANDATORY)
                {
                    msg_error(0, LOG_ERR,
                              "Answer to mandatory request %s not known",
                              request_id_to_string(request_id).c_str());
                    error_message = "Answer to mandatory request unknown";
                }
                else
                    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                              "Answer to optional request %s not known",
                              request_id_to_string(request_id).c_str());
            }

            if(error_message == nullptr)
                wipe_out_alternates(requests, request_id);

            break;
        }
    }

    GVariant *result = g_variant_builder_end(&result_builder);

    unref_collected_requests(requests);

    if(prefsfile != nullptr)
        network_prefs_close(prefsfile);

    if(send_error_if_possible(invocation, error_message))
        g_variant_unref(result);
    else
        tdbus_connman_agent_complete_request_input(object, invocation, result);

    return TRUE;
}

gboolean dbusmethod_connman_agent_request_peer_authorization(tdbusconnmanAgent *object,
                                                             GDBusMethodInvocation *invocation,
                                                             const gchar *arg_peer,
                                                             GVariant *arg_fields,
                                                             void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    send_error_if_possible(invocation, "Peer authorization not supported");

    return TRUE;
}

gboolean dbusmethod_connman_agent_cancel(tdbusconnmanAgent *object,
                                         GDBusMethodInvocation *invocation,
                                         void *user_data)
{
    enter_agent_handler(invocation);

    BUG("%s(): not implemented yet", __func__);
    tdbus_connman_agent_complete_cancel(object, invocation);

    return TRUE;
}
