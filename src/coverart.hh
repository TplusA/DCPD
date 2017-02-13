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
#include <iterator>

#include "gvariantwrapper.hh"

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
    static constexpr size_t STREAM_KEY_SIZE = 16;

    GVariantWrapper stream_key_container_;
    const uint8_t *stream_key_data_;

    bool is_valid_;

  public:
    Tracker(const Tracker &) = delete;
    Tracker &operator=(const Tracker &) = delete;

    explicit Tracker():
        stream_key_data_(nullptr),
        is_valid_(false)
    {}

    bool set(GVariantWrapper &&container);
    bool clear();

    bool is_tracking() const { return is_valid_; }
    bool is_tracking(const GVariantWrapper &stream_key) const;
    const GVariantWrapper &get_variant() const { return stream_key_container_; }
};

class Picture
{
  private:
    static constexpr size_t HASH_SIZE = 16;

    GVariantWrapper hash_;
    const uint8_t *hash_data_;

    GVariantWrapper picture_container_;
    const uint8_t *picture_data_;
    size_t picture_length_;

    bool is_valid_;

  public:
    Picture(const Picture &) = delete;
    Picture &operator=(const Picture &) = delete;

    explicit Picture():
        hash_data_(nullptr),
        picture_data_(nullptr),
        picture_length_(0),
        is_valid_(false)
    {}

    bool set(GVariantWrapper &&hash,
             const uint8_t *hash_data, size_t hash_length,
             GVariantWrapper &&picture_container,
             const uint8_t *picture_data, size_t picture_length);
    bool clear();

    bool is_available() const { return is_valid_; }
    const GVariantWrapper &get_hash_variant() const { return hash_; }

    size_t copy_hash(uint8_t *buffer, size_t buffer_size) const;

    class const_iterator: public std::iterator<std::random_access_iterator_tag, const uint8_t>
    {
      private:
        const uint8_t *const data_;
        const size_t length_;
        size_t pos_;

      public:
        explicit const_iterator(const value_type *data, size_t length,
                                size_t pos = 0):
            data_(data),
            length_(length),
            pos_(pos)
        {}

        bool operator==(const const_iterator &other) const
        {
            return ((this == &other) ||
                    (data_ == other.data_ && length_ == other.length_ &&
                     pos_ == other.pos_));
        }

        bool operator!=(const const_iterator &other) const { return !(*this == other); }
        reference operator*() const { return data_[pos_]; }
        const_iterator &operator++() { ++pos_; return *this; }
        const_iterator operator++(int) { const_iterator ret(*this); ++pos_; return ret; }
        const_iterator &operator--() { --pos_; return *this; }
        const_iterator operator--(int) { const_iterator ret(*this); --pos_; return ret; }
        difference_type operator-(const const_iterator &other) { return pos_ - other.pos_; }
    };

    const_iterator begin() const { return const_iterator(picture_data_, picture_length_); }
    const_iterator end() const   { return const_iterator(picture_data_, picture_length_, picture_length_); }
};

void generate_stream_key_for_app(StreamKey &stream_key, const char *url);

}

#endif /* !COVERART_HH */
