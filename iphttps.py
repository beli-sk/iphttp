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
from select import select
from http.server import HTTPServer, BaseHTTPRequestHandler

from pytun import TunTapDevice

class TunHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print('Processing GET request')
        return self.do_POST(nodata=True)

    def do_POST(self, nodata=False):
        if not nodata:
            print('Processing POST request')
            # reading
            data_len = int(self.headers.get('content-length', 0))
            if data_len:
                data = self.rfile.read(data_len)
            else:
                data = b''
            if data:
                tun.write(data)
        # writing
        self.send_response(200)
        self.send_header("Content-type", "application/octet-stream")
        ret = select([tun], [], [], 0)
        if tun in ret[0]:
            print('data available')
            data = tun.read(tun.mtu)
            self.send_header("Content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            print('no data available from network')
            self.send_header("Content-length", "0")
            self.end_headers()

if __name__ == '__main__':
    tun = TunTapDevice(name='http0')
    tun.addr = '192.168.9.10'
    tun.dstaddr = '192.168.9.11'
    tun.netmask = '255.255.255.0'
    tun.mtu = 1500
    tun.up()

    server_address = ('', int(sys.argv[1]))
    httpd = HTTPServer(server_address, TunHTTPRequestHandler)
    httpd.serve_forever()

