/*
 * Copyright (C) 2017, 2018, 2019, 2022  T+A elektroakustik GmbH & Co. KG
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

#if HAVE_CONFIG_H
#include <config.h>
#endif /* HAVE_CONFIG_H */

#include <glib.h>  /* must be first for #GVariantWrapper */

#include "coverart.hh"
#include "md5.hh"
#include "messages.h"

#include <cstring>

static const uint8_t *extract_data(const GVariantWrapper &container,
                                   size_t expected_length)
{
    if(GVariantWrapper::get(container) == nullptr)
        return nullptr;

    gsize len;
    gconstpointer bytes =
        g_variant_get_fixed_array(GVariantWrapper::get(container),
                                  &len, sizeof(uint8_t));

    const uint8_t *key = static_cast<const uint8_t *>(bytes);

    if(key != nullptr && len != expected_length)
    {
        MSG_BUG("Unexpected stream key length %zu", len);
        key = nullptr;
    }

    return key;
}

bool CoverArt::Tracker::set(GVariantWrapper &&container)
{
    const auto *key(extract_data(container, STREAM_KEY_SIZE));

    if(key == nullptr)
        return clear();

    const bool changed =
        (!is_valid_ ||
         memcmp(stream_key_data_, key, STREAM_KEY_SIZE) != 0);

    if(changed)
    {
        stream_key_container_ = std::move(container);
        stream_key_data_ = key;
        is_valid_ = true;
    }

    return changed;
}

bool CoverArt::Tracker::clear()
{
    if(!is_valid_)
        return false;

    stream_key_container_.release();
    stream_key_data_ = nullptr;
    is_valid_ = false;

    return true;
}

bool CoverArt::Tracker::is_tracking(const GVariantWrapper &stream_key) const
{
    if(!is_tracking())
        return false;

    const auto *key(extract_data(stream_key, STREAM_KEY_SIZE));

    return key != nullptr
        ? (memcmp(stream_key_data_, key, STREAM_KEY_SIZE) == 0)
        : false;
}

static bool equal_hashes(const uint8_t *a, size_t a_len,
                         const uint8_t *b, size_t b_len)
{
    if(a == b)
        return true;
    else if(a == nullptr || b == nullptr)
        return false;
    else if(a_len != b_len)
        return false;
    else
        return memcmp(a, b, a_len) == 0;
}

bool CoverArt::Picture::set(GVariantWrapper &&hash,
                            const uint8_t *hash_data, size_t hash_length,
                            GVariantWrapper &&picture_container,
                            const uint8_t *picture_data, size_t picture_length)
{
    if(picture_data == nullptr || picture_length == 0)
        return clear();

    const bool changed = (!is_valid_ ||
                          !equal_hashes(hash_data_, HASH_SIZE,
                                        hash_data, hash_length));

    if(changed)
    {
        hash_ = std::move(hash);
        hash_data_ = hash_data;
        picture_container_ = std::move(picture_container);
        picture_data_ = picture_data;
        picture_length_ = picture_length;
        is_valid_ = true;
    }

    return changed;
}

bool CoverArt::Picture::clear()
{
    hash_.release();
    hash_data_ = nullptr;
    picture_container_.release();
    picture_length_ = 0;
    picture_data_ = nullptr;

    if(!is_valid_)
        return false;
    else
    {
        is_valid_ = false;
        return true;
    }
}

size_t CoverArt::Picture::copy_hash(uint8_t *buffer, size_t buffer_size) const
{
    if(!is_available())
        return 0;

    if(buffer_size < HASH_SIZE)
        return 0;

    std::copy(hash_data_, hash_data_ + HASH_SIZE, &buffer[0]);

    return HASH_SIZE;
}

void CoverArt::generate_stream_key_for_app(CoverArt::StreamKey &stream_key,
                                           const std::string &url)
{
    MD5::Context ctx;
    MD5::init(ctx);
    MD5::update(ctx, reinterpret_cast<const uint8_t *>(url.data()), url.length());
    MD5::Hash hash;
    MD5::finish(ctx, hash);

    std::copy(hash.begin(), hash.end(), &stream_key.key_[0]);
}
