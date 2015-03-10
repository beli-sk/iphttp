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
import hmac
import hashlib
import base64
import argparse
from select import select
import urllib.request

from pytun import TunTapDevice

def sign(key, data):
    if data is None:
        data = b''
    return base64.b64encode(hmac.new(key.encode('latin1'), msg=data, digestmod=hashlib.md5).digest()).decode('latin1')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IP over HTTP client')
    parser.add_argument('url',
            help='URL of server')
    parser.add_argument('--tun-name', default='http0',
            help='Tunnel interface name (default %(default)s)')
    parser.add_argument('--tun-ip', default=None,
            help='Tunnel local IP address (leave out for manual config)')
    parser.add_argument('--tun-peer',
            help='Tunnel remote IP address')
    parser.add_argument('--tun-mask', default='255.255.255.255',
            help='Tunnel netmask (default %(default)s)')
    parser.add_argument('--tun-mtu', type=int, default=1500,
            help='Tunnel MTU (default %(default)d)')
    parser.add_argument('--key', default=None,
            help='Authentication key (leave out for no authentication)')
    args = parser.parse_args()
    
    tun = TunTapDevice(name=args.tun_name)
    if args.tun_ip:
        tun.addr = args.tun_ip
        tun.dstaddr = args.tun_peer
        tun.netmask = args.tun_mask
        tun.mtu = 1500
        tun.up()
    
    while True:
        ret = select([tun], [], [], 2)
        if tun in ret[0]:
            #print('data available from network')
            data = tun.read(tun.mtu+4)
        else:
            #print('no data from network')
            data = None

        req = urllib.request.Request(args.url, data=data)
        # send signature
        if args.key:
            req.add_header('X-Sig', sign(args.key, data))
        response = urllib.request.urlopen(req)
        data = response.read()
        # verify signature
        if args.key:
            rsig = response.info().get('X-Sig')
            lsig = sign(args.key, data)
            if rsig != lsig:
                print('Bad signature! (%s vs. %s)' % (rsig, lsig))
                continue
        if data:
            #print('received data from http')
            tun.write(data)

