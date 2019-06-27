/*
 * Copyright (C)  2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef REGISTER_PUSH_QUEUE_HH
#define REGISTER_PUSH_QUEUE_HH

#include "logged_lock.hh"
#include "registers_priv.hh"

#include <deque>
#include <stdexcept>

namespace Regs
{

template <typename T>
class PushQueue
{
  private:
    LoggedLock::Mutex lock_;
    std::deque<T> queue_;
    const uint8_t register_;

  public:
    PushQueue(const PushQueue &) = delete;
    PushQueue &operator=(const PushQueue &) = delete;

    explicit PushQueue(uint8_t reg, const char *logged_lock_name):
        register_(reg)
    {
        LoggedLock::configure(lock_, logged_lock_name, MESSAGE_LEVEL_DEBUG);
    }

    void add(T &&item)
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        queue_.emplace_back(std::move(item));
        Regs::get_data().register_changed_notification_fn(register_);
    }

    T take()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);

        if(queue_.empty())
        {
            BUG("No command in register %u queue", register_);
            throw std::out_of_range("");
        }

        const auto result = queue_.front();
        queue_.pop_front();

        return result;
    }

    void reset()
    {
        LOGGED_LOCK_CONTEXT_HINT;
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        queue_.clear();
    }
};

}

#endif /* !REGISTER_PUSH_QUEUE_HH */
