/*
 * Copyright (C) 2016, 2017  T+A elektroakustik GmbH & Co. KG
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

#include <string.h>
#include <ctype.h>
#include <inttypes.h>

#include "connman_agent.h"
#include "dbus_handlers_connman_agent.h"
#include "networkprefs.h"
#include "messages.h"

#define NET_CONNMAN_AGENT_ERROR (net_connman_agent_error_quark())

enum NetConnmanAgentError
{
    NET_CONNMAN_AGENT_ERROR_CANCELED,
    NET_CONNMAN_AGENT_ERROR_REJECTED,
    NET_CONNMAN_AGENT_ERROR_RETRY,
    NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER,
    NET_CONNMAN_AGENT_N_ERRORS,
};

static const GDBusErrorEntry net_connman_agent_error_entries[] =
{
    { NET_CONNMAN_AGENT_ERROR_CANCELED,       "net.connman.Agent.Error.Canceled" },
    { NET_CONNMAN_AGENT_ERROR_REJECTED,       "net.connman.Agent.Error.Rejected" },
    { NET_CONNMAN_AGENT_ERROR_RETRY,          "net.connman.Agent.Error.Retry" },
    { NET_CONNMAN_AGENT_ERROR_LAUNCH_BROWSER, "net.connman.Agent.Error.LaunchBrowser" },
};

G_STATIC_ASSERT(G_N_ELEMENTS(net_connman_agent_error_entries) == NET_CONNMAN_AGENT_N_ERRORS);

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

enum RequestID
{
    /*! Any request not understood by the parser is mapped to this ID */
    REQUEST_UNKNOWN,

    /*! Need name of hidden network */
    REQUEST_NAME,

    /*! Need SSID of hidden network as an alternative to #REQUEST_NAME */
    REQUEST_SSID,

    /*! Username for EAP authentication */
    REQUEST_IDENTITY,

    /*! Passphrase for WEP, PSK, etc. */
    REQUEST_PASSPHRASE,

    /*! Passphrase that was tried, but failed (passphrase changed or wrong) */
    REQUEST_PREVIOUS_PASSPHRASE,

    /*! Request use of WPS */
    REQUEST_WPS_PIN,

    /*! Username for WISPr authentication */
    REQUEST_USERNAME,

    /*! Password for WISPr authentication */
    REQUEST_PASSWORD,

    /*! Stable name for last ID */
    REQUEST_LAST_REQUEST_ID = REQUEST_PASSWORD,
};

enum RequestRequirement
{
    /*! Special ID to express that there was no request for a #RequestID */
    REQREQ_NOT_REQUESTED,

    /*! Answer to request is mandatory, or the request must fail */
    REQREQ_MANDATORY,

    /*! Answer to request is optional, information not required for success */
    REQREQ_OPTIONAL,

    /*! Requested field is an alternative to another field */
    REQREQ_ALTERNATE,

    /*! Field contains information and can be safely ignored */
    REQREQ_INFORMATIONAL,

    /*! Stable name for last ID */
    REQREQ_LAST_REQUEST_REQUIREMENT = REQREQ_INFORMATIONAL,
};

static const char *const request_string_ids[] =
{
    NULL,
    "Name",
    "SSID",
    "Identity",
    "Passphrase",
    "PreviousPassphrase",
    "WPS",
    "Username",
    "Password",
};

static enum RequestID string_to_request_id(const char *string)
{
    G_STATIC_ASSERT(G_N_ELEMENTS(request_string_ids) == REQUEST_LAST_REQUEST_ID + 1);

    for(enum RequestID i = 1; i <= REQUEST_LAST_REQUEST_ID; ++i)
    {
        if(strcmp(request_string_ids[i], string) == 0)
            return i;
    }

    return REQUEST_UNKNOWN;
}

static const char *request_id_to_string(const enum RequestID id)
{
    const char *result = request_string_ids[id];
    return result != NULL ? result : "*UNKNOWN*";
}

static enum RequestRequirement string_to_request_requirement(const char *string)
{
    static const char *const string_ids[] =
    {
        NULL,
        "mandatory",
        "optional",
        "alternate",
        "informational",
    };

    G_STATIC_ASSERT(G_N_ELEMENTS(string_ids) == REQREQ_LAST_REQUEST_REQUIREMENT + 1);

    for(enum RequestRequirement i = 1; i <= REQREQ_LAST_REQUEST_REQUIREMENT; ++i)
    {
        if(strcmp(string_ids[i], string) == 0)
            return i;
    }

    return REQREQ_NOT_REQUESTED;
}

struct Request
{
    enum RequestRequirement requirement;
    uint32_t alternates;
    GVariant *variant;
    bool is_answered;
};

static bool send_error_if_possible(GDBusMethodInvocation *invocation,
                                   const char *error_message)
{
    if(error_message == NULL)
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

    msg_info("Set %s mode", is_wps_mode ? "WPS" : "normal");
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
                                        size_t *tech_length)
{
    const char *const before_service = strrchr(full_service_name, '/');
    const char *const service = before_service + 1;
    const char *const after_tech = (before_service != NULL) ? strchr(service, '_') : NULL;

    *tech_length = after_tech - service;

    return before_service != NULL && after_tech != NULL && *tech_length > 0
        ? service
        : NULL;
}

static const char *delete_service_configuration(const char *full_service_name)
{
    size_t tech_length;
    const char *const service = get_service_basename(full_service_name,
                                                     &tech_length);

    if(service == NULL)
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

    if(prefsfile == NULL)
        return "Failed reading network preferences, cannot delete service";

    const bool succeeded =
        network_prefs_remove_prefs(prefsfile, tech) &&
        network_prefs_write_to_file(prefsfile) == 0;

    network_prefs_close(prefsfile);

    return succeeded ? NULL : "Failed removing service from preferences";
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

        if(error_message != NULL)
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

static void unref_collected_requests(struct Request *requests)
{
    for(enum RequestID i = 0; i <= REQUEST_LAST_REQUEST_ID; ++i)
    {
        if(requests[i].variant != NULL)
        {
            g_variant_unref(requests[i].variant);
            requests[i].variant = NULL;
        }
    }
}

static const char *fill_in_request_requirement(struct Request *request,
                                               GVariant *value)
{
    if(request->requirement != REQREQ_NOT_REQUESTED)
        return "Duplicate request requirement";

    request->requirement =
        string_to_request_requirement(g_variant_get_string(value, NULL));

    if(request->requirement == REQREQ_NOT_REQUESTED)
        return "Unknown request requirement";

    return NULL;
}

static const char *fill_in_alternates(struct Request *request,
                                      GVariant *value)
{
    if(request->alternates != 0)
        return "Duplicate request alternates specification";

    GVariantIter alternates_iter;
    g_variant_iter_init(&alternates_iter, value);

    const gchar *alternate;

    while(g_variant_iter_next(&alternates_iter, "&s", &alternate))
    {
        const enum RequestID request_id = string_to_request_id(alternate);

        if(request_id == REQUEST_UNKNOWN)
            return "Unknown request alternate";

        const uint32_t mask = (1U << (request_id - 1));

        if((request->alternates & mask) != 0)
            return "Duplicate request alternate field";

        request->alternates |= mask;
    }

    if(request->alternates == 0)
        return "Empty request alternates specification";

    return NULL;
}

static const char *collect_requests(struct Request *requests, GVariant *request)
{
    GVariantIter request_iter;
    g_variant_iter_init(&request_iter, request);

    const char *return_string = NULL;

    const gchar *request_key;
    GVariant *request_details;

    while(return_string == NULL &&
          g_variant_iter_next(&request_iter, "{&sv}", &request_key, &request_details))
    {
        const enum RequestID request_id = string_to_request_id(request_key);

        if(request_id == REQUEST_UNKNOWN)
        {
            return_string = "Unknown request";
            goto error_request;
        }

        if(requests[request_id].variant != NULL)
        {
            return_string = "Duplicate request";
            goto error_request;
        }

        GVariantIter detail_iter;
        g_variant_iter_init(&detail_iter, request_details);

        const gchar *detail_key;
        GVariant *detail_value;

        while(return_string == NULL &&
              g_variant_iter_next(&detail_iter, "{&sv}", &detail_key, &detail_value))
        {
            if(strcmp(detail_key, "Requirement") == 0)
                return_string = fill_in_request_requirement(&requests[request_id],
                                                            detail_value);
            else if(strcmp(detail_key, "Alternates") == 0)
                return_string = fill_in_alternates(&requests[request_id],
                                                   detail_value);

            g_variant_unref(detail_value);
        }

        if(requests[request_id].requirement != REQREQ_NOT_REQUESTED)
        {
            g_variant_ref(request_details);
            requests[request_id].variant = request_details;
        }
        else if(return_string == NULL)
            return_string = "Missing request requirement";

error_request:
        g_variant_unref(request_details);
    }

    return return_string;
}

static const char *wps_get_passphrase(void)
{
    /* maybe in a distant future we'll support preset passphrases for WPS */
    return NULL;
}

static const char *wps_get_pin(void)
{
    /* empty string means push-button method */
    return "";
}

static bool insert_answer(GVariantBuilder *result_builder,
                          struct Request *request, enum RequestID request_id,
                          const struct network_prefs *preferences)
{
    /* must match #RequestID enumeration */
    static const char *(*const prefgetters[])(const struct network_prefs *) =
    {
        NULL,
        network_prefs_get_name,
        network_prefs_get_ssid,
        NULL,
        network_prefs_get_passphrase,
        NULL,
        NULL,
        NULL,
        NULL,
    };

    G_STATIC_ASSERT(G_N_ELEMENTS(prefgetters) == REQUEST_LAST_REQUEST_ID + 1);

    /* must match #RequestID enumeration */
    static const char *(*const wpsgetters[])(void) =
    {
        NULL,
        NULL,
        NULL,
        NULL,
        wps_get_passphrase,
        NULL,
        wps_get_pin,
        NULL,
        NULL,
    };

    G_STATIC_ASSERT(G_N_ELEMENTS(wpsgetters) == REQUEST_LAST_REQUEST_ID + 1);

    log_assert(request != NULL);
    log_assert(!request->is_answered);

    if((preferences != NULL && prefgetters[request_id] == NULL) ||
       (preferences == NULL && wpsgetters[request_id] == NULL))
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT, "ConnMan request %s not supported",
                  request_id_to_string(request_id));
        return false;
    }

    const char *const value = preferences != NULL
        ? prefgetters[request_id](preferences)
        : wpsgetters[request_id]();

    if(value == NULL)
    {
        msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                  "Have no answer for ConnMan request %s",
                  request_id_to_string(request_id));
        return false;
    }

    g_variant_builder_add(result_builder, "{sv}",
                          request_string_ids[request_id],
                          g_variant_new_string(value));
    request->is_answered = true;

    return true;
}

static bool insert_alternate_answer(GVariantBuilder *result_builder,
                                    struct Request *requests,
                                    enum RequestID related_id,
                                    const struct network_prefs *preferences)
{
    msg_vinfo(MESSAGE_LEVEL_TRACE,
              "FIND ALTERNATE answer for unanswered request %s",
              request_id_to_string(related_id));

    if(requests[related_id].alternates != 0)
    {
        enum RequestID alternate_id = REQUEST_UNKNOWN;

        for(uint32_t alternates = requests[related_id].alternates;
            alternates != 0;
            alternates >>= 1)
        {
            ++alternate_id;

            if((alternates & 1U) == 0)
                continue;

            log_assert(alternate_id <= REQUEST_LAST_REQUEST_ID);

            if(insert_answer(result_builder, &requests[alternate_id],
                             alternate_id, preferences))
                return true;
            else
                return insert_alternate_answer(result_builder, requests,
                                               alternate_id, preferences);
        }
    }

    msg_vinfo(MESSAGE_LEVEL_TRACE, "No alternate for %s",
              request_id_to_string(related_id));

    return false;
}

static void wipe_out_alternates(struct Request *requests, enum RequestID related_id)
{
    uint32_t alternates = requests[related_id].alternates;

    msg_vinfo(MESSAGE_LEVEL_TRACE, "WIPE OUT alternates 0x%08x for %s",
              alternates, request_id_to_string(related_id));

    if(alternates == 0)
        return;

    requests[related_id].alternates = 0;

    enum RequestID alternate_id = REQUEST_UNKNOWN;

    for(/* nothing */; alternates != 0; alternates >>= 1)
    {
        ++alternate_id;

        if((alternates & 1U) == 0)
            continue;

        log_assert(alternate_id <= REQUEST_LAST_REQUEST_ID);

        msg_vinfo(MESSAGE_LEVEL_TRACE,
                  "Wipe out alternate %s for processed %s",
                  request_id_to_string(alternate_id),
                  request_id_to_string(related_id));

        requests[alternate_id].requirement = REQREQ_NOT_REQUESTED;
        wipe_out_alternates(requests, alternate_id);
    }
}

static const char *
find_preferences_for_service(struct network_prefs_handle **prefsfile,
                             const struct network_prefs **preferences,
                             const char *full_service_name)
{
    *preferences = NULL;

    size_t tech_length;
    const char *const service = get_service_basename(full_service_name,
                                                     &tech_length);

    if(service == NULL)
    {
        *prefsfile = NULL;
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
        *prefsfile = NULL;
        return "Technology unknown";
    }

    if(*prefsfile == NULL)
        return "Failed reading network preferences";

    if(prefs == NULL)
    {
        network_prefs_close(*prefsfile);
        *prefsfile = NULL;
        return "Network preferences not found for service name";
    }

    char buffer[NETWORK_PREFS_SERVICE_NAME_BUFFER_SIZE];

    memcpy(buffer, service, tech_length);
    buffer[tech_length] = '\0';

    if(network_prefs_generate_service_name(prefs, buffer, sizeof(buffer)) == 0)
    {
        network_prefs_close(*prefsfile);
        *prefsfile = NULL;
        return "Network preferences incomplete";
    }

    *preferences = prefs;

    return NULL;
}

gboolean dbusmethod_connman_agent_request_input(tdbusconnmanAgent *object,
                                                GDBusMethodInvocation *invocation,
                                                const gchar *arg_service,
                                                GVariant *arg_fields,
                                                void *user_data)
{
    enter_agent_handler(invocation);

    msg_vinfo(MESSAGE_LEVEL_DEBUG, "Got request for service \"%s\"", arg_service);

    struct network_prefs_handle *prefsfile = NULL;
    const struct network_prefs *preferences = NULL;

    const char *error_message = global_agent_data.is_wps_mode
        ? NULL
        : find_preferences_for_service(&prefsfile, &preferences, arg_service);

    if(send_error_if_possible(invocation, error_message))
        return TRUE;

    struct Request requests[REQUEST_LAST_REQUEST_ID + 1] = {{ 0 }};

    error_message = collect_requests(requests, arg_fields);

    if(send_error_if_possible(invocation, error_message))
    {
        unref_collected_requests(requests);

        if(/* cppcheck-suppress knownConditionTrueFalse */ prefsfile != NULL)
            network_prefs_close(prefsfile);

        return TRUE;
    }

    GVariantBuilder result_builder;
    g_variant_builder_init(&result_builder, G_VARIANT_TYPE ("a{sv}"));

    /* fill in the mandatory requests first, fall back to alternate requests if
     * necessary, fail if not possible */
    for(enum RequestID i = 0; error_message == NULL && i <= REQUEST_LAST_REQUEST_ID; ++i)
    {
        struct Request *const request = &requests[i];

        switch(request->requirement)
        {
          case REQREQ_NOT_REQUESTED:
          case REQREQ_ALTERNATE:
          case REQREQ_INFORMATIONAL:
            continue;

          case REQREQ_MANDATORY:
          case REQREQ_OPTIONAL:
            if(!insert_answer(&result_builder, request, i, preferences) &&
               !insert_alternate_answer(&result_builder, requests, i, preferences))
            {
                if(request->requirement == REQREQ_MANDATORY)
                {
                    msg_error(0, LOG_ERR,
                              "Answer to mandatory request %s not known",
                              request_id_to_string(i));
                    error_message = "Answer to mandatory request unknown";
                }
                else
                    msg_vinfo(MESSAGE_LEVEL_IMPORTANT,
                              "Answer to optional request %s not known",
                              request_id_to_string(i));
            }

            if(error_message == NULL)
                wipe_out_alternates(requests, i);

            break;
        }
    }

    GVariant *result = g_variant_builder_end(&result_builder);

    unref_collected_requests(requests);

    if(prefsfile != NULL)
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
