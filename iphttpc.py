#!/usr/bin/env python3
#
# iphttpc - IP over HTTP client
#
# Copyright 2015 Michal Belica <devel@beli.sk>
#
# This file is part of iphttp.
# 
# iphttp is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# iphttp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with iphttp.  If not, see <http://www.gnu.org/licenses/>.

import sys
from select import select
import urllib.request

from pytun import TunTapDevice

tun = TunTapDevice(name='http1')
tun.addr = '192.168.9.11'
tun.dstaddr = '192.168.9.10'
tun.netmask = '255.255.255.0'
tun.mtu = 1500
tun.up()

while True:
    ret = select([tun], [], [], 2)
    if tun in ret[0]:
        print('data available from network')
        data = tun.read(tun.mtu)
    else:
        print('no data from network')
        data = None

    proxy_support = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_support)
    urllib.request.install_opener(opener)
    req = urllib.request.Request(sys.argv[1], data)
    response = urllib.request.urlopen(req)
    data = response.read()
    if data:
        print('received data from http')
        tun.write(data)
