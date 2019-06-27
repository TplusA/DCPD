/*
 * Copyright (C) 2019  T+A elektroakustik GmbH & Co. KG
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

#ifndef MAINLOOP_HH
#define MAINLOOP_HH

#include "logged_lock.hh"

#include <list>
#include <functional>

namespace MainLoop
{

/*!
 * Simple thread-safe queue of functors.
 */
class Queue
{
  private:
    LoggedLock::Mutex lock_;
    std::list<std::function<void()>> work_;

  public:
    Queue(const Queue &) = delete;
    Queue(Queue &&) = delete;
    Queue &operator=(const Queue &) = delete;
    Queue &operator=(Queue &&) = delete;

    explicit Queue()
    {
        LoggedLock::configure(lock_, "MainLoop::Queue", MESSAGE_LEVEL_DEBUG);
    }

    void add(std::function<void()> &&fn)
    {
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        work_.emplace_back(std::move(fn));
    }

    std::list<std::function<void()>> take()
    {
        std::lock_guard<LoggedLock::Mutex> lock(lock_);
        return std::move(work_);
    }
};

/*!
 * Stuff to be implemented in the main loop code.
 */
namespace detail
{
    extern Queue queued_work;
    void notify_main_loop();
}

/*!
 * Post any work that should be executed by the main loop in main context.
 *
 * This is the only function of concern for client code that wishes to execute
 * some deferred work in the main context. Great for avoiding deadlocks.
 */
static inline void post(std::function<void()> &&fn)
{
    detail::queued_work.add(std::move(fn));
    detail::notify_main_loop();
}

}

#endif /* !MAINLOOP_HH */
