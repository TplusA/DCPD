/*
 * Copyright (C) 2015, 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef DCPREGS_TCPTUNNEL_HH
#define DCPREGS_TCPTUNNEL_HH

#include <cinttypes>
#include <cstdlib>

/*!
 * \addtogroup registers
 */
/*!@{*/

namespace Regs
{

namespace TCPTunnel
{

namespace DCP
{
/*!
 * Open or close TCP tunnel.
 *
 * The implemented command format differs from the original specification.
 * The command expects 2 or 3 bytes, where the first two bytes are the TCP port
 * number (LSB first), and the optional third byte tells the tunnel status
 * (assumed 0 if not sent).
 *
 * A TCP tunnel is opened on the specified port if the third byte is equal to
 * 1, otherwise a possibly existing tunnel on the specified port is closed.
 *
 * A port number of 0 is considered invalid (though it actually isn't,
 * technically) and is rejected.
 */
int write_119_tcp_tunnel_control(const uint8_t *data, size_t length);

/*!
 * Receive data from a networked device over the TCP tunnel.
 *
 * The implemented command format differs from the original specification.
 * Data is prefixed with three bytes, where the first two bytes are the TCP
 * port number of the TCP tunnel the peer has connected to (LSB first), and the
 * third byte is a peer ID to be used when sending data through register 121.
 */
ssize_t read_120_tcp_tunnel_read(uint8_t *response, size_t length);

/*!
 * Send data to a networked device over the TCP tunnel.
 *
 * The implemented command format differs from the original specification.
 * Data is prefixed with three bytes, where the first two bytes are the TCP
 * port number of an open TCP tunnel (LSB first), and the third byte is the
 * peer ID as received from register 120.
 */
int write_121_tcp_tunnel_write(const uint8_t *data, size_t length);
}

}

}

/*!@}*/

#endif /* !DCPREGS_TCPTUNNEL_HH */
