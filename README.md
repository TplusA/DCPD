# DCP daemon

## Copyright and contact

DCPD is released under the terms of the GNU General Public License version 3
(GPLv3). See file <tt>COPYING</tt> for licensing terms.

Contact:

    T+A elektroakustik GmbH & Co. KG
    Planckstrasse 11
    32052 Herford
    Germany

## Short description

The _dcpd_ daemon implements a subset of DCP, the Device Control Protocol. This
daemon does not implement the SPI physical layer communcation, but only knows
about the high-level structure of DCP.

The program is written in C++14.

## Communication with other system processes

Any register read and write command is forwarded to some responsible system
daemon using _D-Bus_ signals. Software components that are interested in
certain information need to subscribe to these _D-Bus_ signals so that they can
see them.

The reason why _dcpd_ uses _D-Bus_ signals instead of direct messages is that
_dcpd_, being one of the most low-level components, should not know how the
rest of the system is structured. For instance, it should not know who exactly
is going to handle the DRC "Play" command---possibly there is more than one
process that needs to see the information. Keeping such detailed knowledge
about the system inside _dcpd_ would mean a big maintainance burden while the
system evolves.

## Communication with _dcpspi_

> **Note:** This is a temporary construction that avoids creating a kernel
>     module early in the project.

The _dcpd_ daemon connects to _dcpspi_ using two named pipes, one for sending
and one for receiving DCP data.

All register accesses are range checked by _dcpd_ (_dcpspi_ does not know
enough about registers).

## Communication with _drcpd_

The _drcpd_ daemon connects to _dcpd_ using two named pipes created by _dcpd_.

Any XML DRC protocol data that _drcpd_ needs to send are handed over the named
pipe to _dcpd_ (the pipe going back into _drcpd_ is used for synchronization
purposes). This data is encapsulated into DCP packets as is by _dcpd_, which
sends it further on to _dcpspi_.

DRC command codes written to the remote control register are translated to
_D-Bus_ signals just like most of the other register write accesses. Many of
them will end up being handled by _drcpd_.


# Protocol handling

## Basic control packets

There are four meaningful commands in the control protocol:

- fixed write register (0x00),
- fixed read register (0x01),
- variable write register (0x02), and
- variable read register (0x03).

## Registers

The list of implemented registers is found in the source code, more
specifically in the <code>register_map</code> array in file
<code>src/registers.cc</code>, found near the end of the file.
