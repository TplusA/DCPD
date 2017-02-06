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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <cstring>
#include <algorithm>

#include "coverart.hh"
#include "md5.hh"
#include "messages.h"

bool CoverArt::Tracker::set(const uint8_t *key, size_t key_length)
{
    if(key == nullptr || key_length != 16)
    {
        if(key != nullptr)
            BUG("Unexpected stream key length %zu", key_length);

        return clear();
    }

    const bool changed =
        (!is_valid_ ||
         memcmp(stream_key_.key_, key, sizeof(stream_key_.key_)) != 0);

    if(changed)
    {
        memcpy(stream_key_.key_, key, sizeof(stream_key_.key_));
        is_valid_ = true;
    }

    return changed;
}

bool CoverArt::Tracker::clear()
{
    if(!is_valid_)
        return false;
    else
    {
        is_valid_ = false;
        return true;
    }
}

void CoverArt::generate_stream_key_for_app(CoverArt::StreamKey &key, const char *url)
{
    MD5::Context ctx;
    MD5::init(ctx);
    MD5::update(ctx, static_cast<const uint8_t *>(static_cast<const void *>(url)), strlen(url));
    MD5::Hash hash;
    MD5::finish(ctx, hash);

    std::copy(hash.begin(), hash.end(), &key.key_[0]);
}
