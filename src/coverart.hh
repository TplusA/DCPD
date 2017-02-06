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

#include <cinttypes>
#include <cstdlib>

#ifndef COVERART_HH
#define COVERART_HH

namespace CoverArt
{

struct StreamKey
{
    uint8_t key_[16];
};

class Tracker
{
  private:
    StreamKey stream_key_;
    bool is_valid_;

  public:
    Tracker(const Tracker &) = delete;
    Tracker &operator=(const Tracker &) = delete;

    explicit Tracker():
        stream_key_{0},
        is_valid_(false)
    {}

    bool set(const uint8_t *key, size_t key_length);
    bool clear();

    bool is_tracking() const { return is_valid_; }
    const StreamKey &get() const { return stream_key_; }
};

void generate_stream_key_for_app(StreamKey &stream_key, const char *url);

}

#endif /* !COVERART_HH */
