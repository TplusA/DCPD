/*
 * Copyright (C) 2018, 2019  T+A elektroakustik GmbH & Co. KG
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

#include <cppcutter.h>

#include "mock_network.hh"

enum class NetworkFn
{
    create_socket,
    accept_peer_connection,
    have_data,
    close,

    first_valid_network_fn_id = create_socket,
    last_valid_network_fn_id = close,
};

static std::ostream &operator<<(std::ostream &os, const NetworkFn id)
{
    if(id < NetworkFn::first_valid_network_fn_id ||
       id > NetworkFn::last_valid_network_fn_id)
    {
        os << "INVALID";
        return os;
    }

    switch(id)
    {
      case NetworkFn::create_socket:
        os << "create_socket";
        break;

      case NetworkFn::accept_peer_connection:
        os << "accept_peer_connection";
        break;

      case NetworkFn::have_data:
        os << "have_data";
        break;

      case NetworkFn::close:
        os << "close";
        break;
    }

    os << "()";

    return os;
}

class MockNetwork::Expectation
{
  public:
    struct Data
    {
        const NetworkFn function_id_;

        int ret_int_;
        bool ret_bool_;
        uint16_t socket_port_;
        int socket_backlog_;
        int fd_arg_;
        bool bool_arg_;
        enum MessageVerboseLevel verbose_level_;

        explicit Data(NetworkFn fn):
            function_id_(fn),
            ret_int_(-987123),
            ret_bool_(false),
            socket_port_(25),
            socket_backlog_(9001),
            fd_arg_(-20),
            bool_arg_(false),
            verbose_level_(MESSAGE_LEVEL_IMPORTANT)
        {}
    };

    const Data d;

  private:
    /* writable reference for simple ctor code */
    Data &data_ = *const_cast<Data *>(&d);

  public:
    Expectation(const Expectation &) = delete;
    Expectation &operator=(const Expectation &) = delete;

    explicit Expectation(int ret, uint16_t port, int backlog):
        d(NetworkFn::create_socket)
    {
        data_.ret_int_ = ret;
        data_.socket_port_ = port;
        data_.socket_backlog_ = backlog;
    }

    explicit Expectation(int ret, int server_fd, bool non_blocking,
                         enum MessageVerboseLevel verbose_level):
        d(NetworkFn::accept_peer_connection)
    {
        data_.ret_int_ = ret;
        data_.fd_arg_ = server_fd;
        data_.bool_arg_ = non_blocking;
        data_.verbose_level_ = verbose_level;
    }

    explicit Expectation(int ret, int peer_fd):
        d(NetworkFn::have_data)
    {
        data_.fd_arg_ = peer_fd;
    }

    explicit Expectation(int fd):
        d(NetworkFn::close)
    {
        data_.fd_arg_ = fd;
    }

    Expectation(Expectation &&) = default;
};


MockNetwork::MockNetwork()
{
    expectations_ = new MockExpectations();
}

MockNetwork::~MockNetwork()
{
    delete expectations_;
}

void MockNetwork::init()
{
    cppcut_assert_not_null(expectations_);
    expectations_->init();
}

void MockNetwork::check() const
{
    cppcut_assert_not_null(expectations_);
    expectations_->check();
}

void MockNetwork::expect_create_socket(int ret, uint16_t port, int backlog)
{
    expectations_->add(Expectation(ret, port, backlog));
}

void MockNetwork::expect_accept_peer_connection(int ret, int server_fd, bool non_blocking, enum MessageVerboseLevel verbose_level)
{
    expectations_->add(Expectation(ret, server_fd, non_blocking, verbose_level));
}

void MockNetwork::expect_have_data(bool ret, int peer_fd)
{
    expectations_->add(Expectation(ret, peer_fd));
}

void MockNetwork::expect_close(int fd)
{
    expectations_->add(Expectation(fd));
}


MockNetwork *mock_network_singleton = nullptr;

int network_create_socket(uint16_t port, int backlog)
{
    const auto &expect(mock_network_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, NetworkFn::create_socket);
    cppcut_assert_equal(expect.d.socket_port_, port);
    cppcut_assert_equal(expect.d.socket_backlog_, backlog);

    return expect.d.ret_int_;
}

int network_accept_peer_connection(int server_fd, bool non_blocking,
                                   enum MessageVerboseLevel verbose_level)
{
    const auto &expect(mock_network_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, NetworkFn::accept_peer_connection);
    cppcut_assert_equal(expect.d.fd_arg_, server_fd);
    cppcut_assert_equal(expect.d.bool_arg_, non_blocking);
    cppcut_assert_equal(expect.d.verbose_level_, verbose_level);

    return expect.d.ret_int_;
}

bool network_have_data(int peer_fd)
{
    const auto &expect(mock_network_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, NetworkFn::have_data);
    cppcut_assert_equal(expect.d.fd_arg_, peer_fd);

    return expect.d.ret_bool_;
}

void network_close(int *fd)
{
    const auto &expect(mock_network_singleton->expectations_->get_next_expectation(__func__));

    cppcut_assert_equal(expect.d.function_id_, NetworkFn::close);
    cppcut_assert_not_null(fd);
    cppcut_assert_equal(expect.d.fd_arg_, *fd);

    *fd = -1;
}
