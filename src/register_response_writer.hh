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

#ifndef REGISTER_RESPONSE_WRITER_HH
#define REGISTER_RESPONSE_WRITER_HH

#include <string>

class RegisterResponseWriter
{
  private:
    uint8_t *const response_;
    const size_t length_;

    size_t pos_;
    bool overflown_;

  public:
    RegisterResponseWriter(const RegisterResponseWriter &) = delete;
    RegisterResponseWriter(RegisterResponseWriter &&) = default;
    RegisterResponseWriter &operator=(const RegisterResponseWriter &) = delete;
    RegisterResponseWriter &operator=(RegisterResponseWriter &&) = default;

    explicit RegisterResponseWriter(uint8_t *const response, size_t length):
        response_(response),
        length_(length),
        pos_(0),
        overflown_(length_ == 0)
    {}

    void push_back(uint8_t byte)
    {
        if(overflown_)
            return;

        if(pos_ < length_)
            response_[pos_++] = byte;
        else
            overflown_ = true;
    }

    void push_back(const std::string &str)
    {
        if(str.copy(reinterpret_cast<char *>(response_ + pos_),
                    remaining_space()) == str.length())
        {
            pos_ += str.length();
            push_back(uint8_t(0));
        }
        else
        {
            pos_ = length_;
            overflown_ = true;
        }
    }

    bool is_overflown() const { return overflown_; }

    size_t get_length() const { return pos_; }

  private:
    size_t remaining_space() const
    {
        return pos_ < length_ ? length_ - pos_ : 0;
    }
};

#endif /* !REGISTER_RESPONSE_WRITER_HH */
