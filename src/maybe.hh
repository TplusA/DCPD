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

template <typename T>
class Maybe
{
  private:
    bool is_value_known_;
    T value_;

  public:
    Maybe(const Maybe &) = delete;
    Maybe(Maybe &&) = default;
    Maybe &operator=(const Maybe &) = default;

    explicit Maybe():
        is_value_known_(false),
        value_()
    {}

    explicit Maybe(const T &value):
        is_value_known_(true),
        value_(value)
    {}

    explicit Maybe(T &&value):
        is_value_known_(true),
        value_(std::move(value))
    {}

    void set_unknown()
    {
        is_value_known_ = false;
        value_ = T();
    }

    T &operator=(T &&value)
    {
        value_ = value;
        is_value_known_ = true;
        return value_;
    }

    void set_known() { is_value_known_ = true; }
    bool is_known() const { return is_value_known_; }

    const T &get() const { return value_; }
    T &get_rw() { return value_; }

    bool operator==(const T &other) const { return is_value_known_ ? value_ == other : false; }
    bool operator!=(const T &other) const { return is_value_known_ ? value_ != other : false; }

    bool operator==(const Maybe &other) const
    {
        if(other.is_value_known_)
            return *this != other.value_;
        else
            return !is_value_known_;
    }

    bool operator!=(const Maybe &other) const
    {
        if(other.is_value_known_)
            return *this == other.value_;
        else
            return is_value_known_;
    }

    template <typename TOut>
    const TOut &pick(const TOut &if_yes, const TOut &if_no, const TOut &if_unknown) const
    {
        return is_value_known_
            ? (value_ ? if_yes : if_no)
            : if_unknown;
    }
};
