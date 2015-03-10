#!/usr/bin/env python3
#
# iphttps - IP over HTTP server
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
from http.server import HTTPServer, BaseHTTPRequestHandler

from pytun import TunTapDevice

key = None

class TunHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print('Processing GET request')
        return self.do_POST(nodata=True)

    def do_POST(self, nodata=False):
        global key
        if nodata:
            data = b''
        else:
            print('Processing POST request')
            # reading
            data_len = int(self.headers.get('content-length', 0))
            if data_len:
                data = self.rfile.read(data_len)
            else:
                data = b''
        # verify signature
        if key:
            rsig = self.headers.get('X-Sig')
            lsig = base64.b64encode(hmac.new(key.encode('latin1'), msg=data, digestmod=hashlib.md5).digest()).decode('latin1')
            if rsig != lsig:
                print('Bad signature (%s vs %s) %d (%s)'% (rsig, lsig, data_len, base64.b64encode(data)))
                print(''.join(('%s: %s\n' % (k, v) for k,v in self.headers.items())))
                self.send_error(400)
                return
        if data:
            tun.write(data)
        # writing
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        ret = select([tun], [], [], 0)
        if tun in ret[0]:
            print('data available')
            data = tun.read(tun.mtu+4)
            self.send_header("Content-length", str(len(data)))
            # send signature
            if key:
                sig = base64.b64encode(hmac.new(key.encode('latin1'), msg=data, digestmod=hashlib.md5).digest()).decode('latin1')
                self.send_header("X-Sig", sig)
            self.end_headers()
            self.wfile.write(data)
        else:
            print('no data available from network')
            self.send_header("Content-length", "0")
            # send signature
            if key:
                sig = base64.b64encode(hmac.new(key.encode('latin1'), msg=b'', digestmod=hashlib.md5).digest()).decode('latin1')
                self.send_header("X-Sig", sig)
            self.end_headers()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='IP over HTTP client')
    parser.add_argument('port', type=int,
            help='Port to listen on')
    parser.add_argument('--bind', default='',
            help='Address to bind to (leave out for any)')
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

    key = args.key

    tun = TunTapDevice(name=args.tun_name)
    if args.tun_ip:
        tun.addr = args.tun_ip
        tun.dstaddr = args.tun_peer
        tun.netmask = args.tun_mask
        tun.mtu = args.tun_mtu
        tun.up()

    server_address = (args.bind, args.port)
    httpd = HTTPServer(server_address, TunHTTPRequestHandler)
    httpd.serve_forever()

