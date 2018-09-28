/*
 * Copyright (C) 2018  T+A elektroakustik GmbH & Co. KG
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

#include "network_netlink.hh"

#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <array>
#include <fstream>

static const std::string sysfs_net_path("/sys/class/net/");

static Connman::Technology determine_technology(const char *if_name)
{
    const auto filename(sysfs_net_path + if_name + "/uevent");

    std::ifstream f(filename.c_str());

    while(f.good())
    {
        std::string temp;
        f >> temp;

        if(temp == "DEVTYPE=wlan")
            return Connman::Technology::WLAN;
    }

    return Connman::Technology::ETHERNET;
}

static Connman::Address<Connman::AddressType::MAC>
determine_mac_address(const char *if_name)
{
    const auto filename(sysfs_net_path + if_name + "/address");

    std::ifstream f(filename.c_str());
    std::string address_string;
    f >> address_string;

    try
    {
        return Connman::Address<Connman::AddressType::MAC>(std::move(address_string));
    }
    catch(const std::domain_error &e)
    {
        /* handled below */
    }

    return Connman::Address<Connman::AddressType::MAC>();
}

static void add_link_if_interesting(const struct nlmsghdr *const link,
                                    Network::NetlinkList &devices)
{
    const auto *const iface = static_cast<struct ifinfomsg *>(NLMSG_DATA(link));
    auto len = link->nlmsg_len - NLMSG_LENGTH(sizeof(*iface));

    for(const auto *attr = IFLA_RTA(iface); RTA_OK(attr, len); attr = RTA_NEXT(attr, len))
    {
        if(attr->rta_type != IFLA_IFNAME)
            continue;

        if(iface->ifi_type != ARPHRD_ETHER)
            continue;

        const char *dev_name(static_cast<const char *>(RTA_DATA(attr)));
        const auto tech = determine_technology(dev_name);
        auto mac = determine_mac_address(dev_name);

        switch(tech)
        {
          case Connman::Technology::UNKNOWN_TECHNOLOGY:
            break;

          case Connman::Technology::ETHERNET:
          case Connman::Technology::WLAN:
            if(!mac.empty())
                devices.emplace_back(dev_name, std::move(mac), tech);

            break;
        }
    }
}

static bool extract_interfaces(int fd, Network::NetlinkList &devices)
{
    struct sockaddr_nl addr {0};
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;

    if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        msg_error(errno, LOG_ERR, "Failed binding to netlink socket");
        return false;
    }

    struct nl_req_s
    {
        struct nlmsghdr hdr;
        struct rtgenmsg gen;
    };

    struct nl_req_s req {0};
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.hdr.nlmsg_pid = getpid();
    req.gen.rtgen_family = AF_PACKET;

    struct iovec io;
    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;

    struct sockaddr_nl kernel {0};
    kernel.nl_family = AF_NETLINK;

    struct msghdr msg {0};
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_name = &kernel;
    msg.msg_namelen = sizeof(kernel);

    if(sendmsg(fd, static_cast<struct msghdr *>(&msg), 0) < 0)
    {
        msg_error(errno, LOG_ERR, "Failed sending message to netlink socket");
        return false;
    }

    while(true)
    {
        std::array<uint8_t, 16 * 1024> reply_buffer;
        io.iov_base = reply_buffer.data();
        io.iov_len = reply_buffer.size();

        struct msghdr reply;
        reply.msg_iov = &io;
        reply.msg_iovlen = 1;
        reply.msg_name = &kernel;
        reply.msg_namelen = sizeof(kernel);

        ssize_t len = recvmsg(fd, &reply, 0);

        if(len < 0)
        {
            msg_error(errno, LOG_ERR,
                      "Failed receiving messages from netlink socket");
            return false;
        }

        if(len == 0)
            continue;

        for(auto *msg_ptr = reinterpret_cast<struct nlmsghdr *>(reply_buffer.data());
            NLMSG_OK(msg_ptr, len);
            msg_ptr = NLMSG_NEXT(msg_ptr, len))
        {
            switch(msg_ptr->nlmsg_type)
            {
              case NLMSG_DONE:
                return true;

              case RTM_NEWLINK:
                add_link_if_interesting(msg_ptr, devices);
                break;
            }
        }
    }
}

Network::NetlinkList Network::os_get_network_devices()
{
    std::vector<std::tuple<std::string,
                           Connman::Address<Connman::AddressType::MAC>,
                           Connman::Technology>> devices;

    int netlink_socket = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if(netlink_socket < 0)
    {
        msg_error(errno, LOG_ERR, "Failed creating netlink socket");
        return devices;
    }

    if(!extract_interfaces(netlink_socket, devices))
        devices.clear();

    close(netlink_socket);

    return devices;
}
