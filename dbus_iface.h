#ifndef DBUS_IFACE_H
#define DBUS_IFACE_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int dbus_setup(bool connect_to_session_bus);
void dbus_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* !DBUS_IFACE_H */
