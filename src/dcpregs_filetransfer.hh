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

#ifndef DCPREGS_FILETRANSFER_HH
#define DCPREGS_FILETRANSFER_HH

#include "coverart.hh"

/*!
 * \addtogroup registers
 */
/*!@{*/

void dcpregs_filetransfer_set_picture_provider(const CoverArt::PictureProviderIface &provider);

/*!@}*/

#endif /* !DCPREGS_FILETRANSFER_HH */
