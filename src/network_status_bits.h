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

#ifndef NETWORK_STATUS_BITS_H
#define NETWORK_STATUS_BITS_H

/* first byte */
#define NETWORK_STATUS_IPV4_NOT_CONFIGURED      ((uint8_t)0x00)
#define NETWORK_STATUS_IPV4_STATIC_ADDRESS      ((uint8_t)0x01)
#define NETWORK_STATUS_IPV4_DHCP                ((uint8_t)0x02)

/* second byte */
#define NETWORK_STATUS_DEVICE_NONE              ((uint8_t)0x00)
#define NETWORK_STATUS_DEVICE_ETHERNET          ((uint8_t)0x01)
#define NETWORK_STATUS_DEVICE_WLAN              ((uint8_t)0x02)

/* third byte */
#define NETWORK_STATUS_CONNECTION_NONE          ((uint8_t)0)
#define NETWORK_STATUS_CONNECTION_CONNECTED     ((uint8_t)1 << 0)
#define NETWORK_STATUS_CONNECTION_CONNECTING    ((uint8_t)1 << 6)
#define NETWORK_STATUS_CONNECTION_IS_WPS_MODE   ((uint8_t)1 << 7)

#endif /* !NETWORK_STATUS_BITS_H */
