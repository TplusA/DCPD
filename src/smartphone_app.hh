/*
 * Copyright (C) 2016, 2018  T+A elektroakustik GmbH & Co. KG
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

#ifndef SMARTPHONE_APP_HH
#define SMARTPHONE_APP_HH

#include <string>
#include <deque>
#include <map>
#include <mutex>
#include <memory>
#include <functional>

#include "network.h"
#include "applink.hh"

namespace Applink
{

class Peer
{
  private:
    struct SendQueue
    {
        std::mutex lock_;
        std::deque<std::string> queue_;
        const std::function<void(int)> &notify_have_outgoing_fn_;
        std::function<void(int, bool)> notify_peer_died_fn_;

        explicit SendQueue(const std::function<void(int)> &out_notification,
                           std::function<void(int, bool)> &&died_notification):
            notify_have_outgoing_fn_(out_notification),
            notify_peer_died_fn_(died_notification)
        {}
    };

    InputBuffer input_buffer_;
    SendQueue send_queue_;

  public:
    Peer(const Peer &) = delete;
    Peer &operator=(const Peer &) = delete;

    explicit Peer(int fd, const std::function<void(int)> &out_fn,
                  std::function<void(int, bool)> &&died_fn):
        send_queue_(out_fn, std::move(died_fn))
    {}

    bool handle_incoming_data(int fd);
    void send_to_queue(int fd, std::string &&command);
    bool send_one_from_queue_to_peer(int fd);
};

/*!
 * A TCP/IP connection to a smartphone.
 *
 * This is basically a pair of socket file descriptors, one for the server
 * side, and one for the single supported peer. Multiple simultaneous
 * connections are not supported.
 */
class AppConnections
{
  private:
    std::mutex lock_;
    int server_fd_;

    const std::function<void(int)> send_queue_filled_notification_fn_;
    std::map<int, std::unique_ptr<Peer>> peers_;

  public:
    AppConnections(const AppConnections &) = delete;
    AppConnections &operator=(const AppConnections &) = delete;

    /*!
     * Initialize connection data.
     *
     * \param send_notification_fn
     *     Function that is called whenever there is a command in the output
     *     command queue.
     */
    explicit AppConnections(std::function<void(int)> &&send_notification_fn):
        server_fd_(-1),
        send_queue_filled_notification_fn_(std::move(send_notification_fn))
    {}

    bool listen(uint16_t port);
    void close();

    void process_out_queue();
    void send_to_all_peers(std::string &&command);

  private:
    bool add_new_peer(int peer_fd);
    void close_and_forget_peer(int peer_fd,
                               bool is_registered_with_dispatcher = true);

    bool handle_new_peer(int server_fd);
    void handle_peer_died(int peer_fd);
};

}

#endif /* !SMARTPHONE_APP_HH */
