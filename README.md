# DCP daemon

The _dcpd_ daemon implements a subset of DCP, the Device Control Protocol. This
daemon does not implement the SPI physical layer communcation, but only knows
about the high-level structure of DCP.

The program is written in C11.

## Communication with _dcpspi_

**Note:** This is a temporary construction that avoids creating of a kernel
    module early in the project.

The _dcpd_ daemon connects to _dcpspi_ using two named pipes, one for sending
and one for receiving DCP data.

## Communication with _drcpd_

Any DRC protocol data is directly handed over the _drcpd_ using a named pipe.
Also, _drcpd_ may send DRC protocol data to _dcpd_, which is encapsulated into
the corresponding DCP packet.

## Communication with any other system process

Any register read and write command is forwarded to some responsible system
daemon using _D-Bus_ messages.


# Protocol handling

## Basic control packets

There are four meaningful commands in the control protocol:

- fixed write register (0x00),
- fixed read register (0x01),
- variable write register (0x02), and
- variable read register (0x03).

Command 0x04 ("Read All Registers") is undocumented and thus remains
unimplemented.

The control flow commands XON and XOFF (0x0e, 0x0f) are used for pausing and
resuming a transfer to avoid lost bytes due to full receive buffers. Since
these are not used on SPI, they also remain unimplemented.

## Registers

The list of implemented registers is found in the source code, more
specifically in the <code>register_map</code> array in file
<code>registers.c</code>, found near the end of the file.
