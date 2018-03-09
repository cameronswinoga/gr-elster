#!/usr/bin/env python

# Copyright 2013-2014 Clayton Smith
#
# This file is part of gr-elster
#
# gr-elster is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# gr-elster is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gr-elster; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

import sys
import struct
import time
import datetime
import logging as log

log.basicConfig(level=log.INFO)

meter_first_hour = {}
meter_last_hour = {}
meter_readings = {}

meter_parents = {}
meter_gatekeepers = {}
meter_levels = {}

def add_hourly(meter, last_hour, readings):
    first_hour = last_hour - len(readings) + 1
    if meter not in meter_readings:
        meter_first_hour[meter] = first_hour
        meter_last_hour[meter] = last_hour
        meter_readings[meter] = [-1] * 65536
    if (first_hour - meter_first_hour[meter]) % 65536 > 32768:
        meter_first_hour[meter] = first_hour
    if (last_hour - meter_last_hour[meter]) % 65536 < 32768:
        meter_last_hour[meter] = last_hour
    for i in range(len(readings)):
        meter_readings[meter][i + first_hour] = readings[i]

def decode_ts(bytes):
    ts1, ts2, ts3 = struct.unpack(">BBB", bytes)
    ts = ((ts1 << 16) + (ts2 << 8) + ts3)
    ts_h = ts / 128 / 3600
    ts -= ts_h * 128 * 3600
    ts_m = ts / 128 / 60
    ts -= ts_m * 128 * 60
    ts_s = ts / 128.
    return ts_h, ts_m, ts_s

def decode_date(bytes):
    short, = struct.unpack(">H", bytes)
    year = 2000 + (short >> 9)
    days = short & 0x1FF
    date = datetime.date(year, 1, 1)
    delta = datetime.timedelta(days)
    return date + delta

def to_hex(bytes):
    return "".join(["{0:02x}".format(ord(byte)) for byte in bytes])

def decode_pkt(t, pkt):
    packet_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t))
    l1, flag1, src, dst, unk1, unk2, unk3 = struct.unpack(">BBIIBBB", pkt[0:13])
    packet_str += "len={0:02x} flag={1:02x} src={2:08x} dst={3:08x} {4:02x}{5:02x}{6:02x}".format(l1, flag1, src, dst, unk1, unk2, unk3)
    if (src & 0x80000000) or (dst == 0 and l1 >= 35):
        ts_h, ts_m, ts_s = decode_ts(pkt[13:16])
        packet_str += "ts={0:02}:{1:02}:{2:06.3f}".format(ts_h, ts_m, ts_s)
    else:
        packet_str += ("rpt=" + to_hex(pkt[13:14]) + " " + to_hex(pkt[14:16]))

    if dst == 0 and l1 >= 35: # flood broadcast message
        unk4, unk5, hop, unk7, addr, unk8, l2 = struct.unpack(">BBBBIIB", pkt[16:29])
        packet_str += "{0:02x}{1:02x} hop={2:02x} {3:02x} addr={4:08x} {5:08x} len={6:02x}".format(unk4, unk5, hop, unk7, addr, unk8, l2)
        if l2 == 0:
            packet_str += to_hex(pkt[29:33])
            unk9, l3 = struct.unpack(">BB", pkt[33:35])
            packet_str += "{0:02x}".format(unk9)
            packet_str += ("next_" + str(l3) + "_days=" + to_hex(pkt[35:]))
        elif l2 == 6:
            packet_str += to_hex(pkt[29:33])
            packet_str += "date=" + str(decode_date(pkt[33:35]))
        elif l2 == 0x27:
            packet_str += to_hex(pkt[29:33])
            for x in range(7): # 7 meter numbers (with first bit sometimes set to 1) followed by number 0x01-0x45
                packet_str += to_hex(pkt[33 + 5*x:37 + 5*x])
                packet_str += to_hex(pkt[37 + 5*x:38 + 5*x])
        else:
            packet_str += to_hex(pkt[29:])
        log.debug(packet_str)
    else:
        if src & 0x80000000:
            packet_str += "path=" + to_hex(pkt[16:24])
            if ord(pkt[24]) == 0x40:
                packet_str += to_hex(pkt[24:28])
                l4, unk12, cmd, cnt = struct.unpack(">BBBB", pkt[28:32])
                packet_str += "len={0:02x} {1:02x} cmd={2:02x} cnt={3:02x}".format(l4, unk12, cmd, cnt)

                if cmd == 0xce: # fetch hourly usage data, every 6 hours
                    unk13, hour = struct.unpack(">BH", pkt[32:])
                    packet_str += "{0:02x} first_hour={1:05}".format(unk13, hour)
                elif cmd == 0x22:
                    packet_str += to_hex(pkt[32:])
                elif cmd == 0x23: # path building stuff? every 6 hours
                    unk14, unk15, unk16, your_id, parent_id, parent, unk17, n_children, unk19, level, unk21, unk22, unk23, unk24, unk25, unk26, unk27, unk28, unk29 = struct.unpack(">BBBBBIBBBBBBBBBBHIB", pkt[32:58])
                    packet_str += "{0:02x} {1:02x} {2:02x} id={3:02x} par_id={4:02x} parent={5:08x} {6:02x} #child={7} {8:02x} lvl={9} {10:02x}{11:02x}{12:02x} {13:02x} {14:02x} {15:02x} {16:04x} {17:08x} {18:02x}".format(
                            unk14, unk15, unk16, your_id, parent_id, parent, unk17, n_children, unk19, level, unk21, unk22, unk23, unk24, unk25, unk26, unk27, unk28, unk29)
                    if l4 == 0x20:
                        packet_str += "{0:02x}".format(ord(pkt[58]))
                        packet_str += "date=" + str(decode_date(pkt[59:61]))

                    # Prepare graph edges
                    meter_parents[dst] = parent
                    if level == 2:
                        meter_parents[parent] = src # Fill this in now, in case we don't hear from parent

                    meter_gatekeepers[dst] = src
                    if level >= 2:
                        meter_gatekeepers[parent] = src # Fill this in now, in case we don't hear from parent

                    meter_levels[dst] = level
                    meter_levels[parent] = level - 1
                    meter_levels[src] = 0
                elif cmd == 0x28:
                    packet_str += to_hex(pkt[32:])
                elif cmd == 0x6a:
                    packet_str += to_hex(pkt[32:])
                else: # unknown command
                    packet_str += to_hex(pkt[32:])
            else:
                packet_str += to_hex(pkt[24:])
            log.debug(packet_str)
        else:
            if len(pkt) > 16:
                l4 = ord(pkt[16])
                if l4 == l1 - 17: # 1st byte of payload is a length
                    if len(pkt) > 18:
                        cmd = ord(pkt[18])
                        if cmd == 0xce: # hourly usage data, every 6 hours
                            unk10, cmd, ctr, unk11, flag2, curr_hour, last_hour, n_hours = struct.unpack(">BBBBBHHB", pkt[17:27])
                            packet_str += "len={0:02x} {1:02x} cmd={2:02x} ctr={3:02x} {4:02x} {5:02x} cur_hour={6:05} last_hour={7:05} n_hour={8:02}".format(l4, unk10, cmd, ctr, unk11, flag2, curr_hour, last_hour, n_hours)
                            packet_str += to_hex(pkt[27:])
                            add_hourly(src, last_hour, struct.unpack(">" + "H"*n_hours, pkt[27:27 + 2*n_hours]))
                            # TODO: Get total meter reading
                        elif cmd == 0x22: # just an acknowledgement
                            unk10, cmd, ctr = struct.unpack(">BBB", pkt[17:20])
                            packet_str += "len={0:02x} {1:02x} cmd={2:02x} ctr={3:02x}".format(l4, unk10, cmd, ctr)
                            packet_str += to_hex(pkt[20:])
                        elif cmd == 0x23: # path building stuff? every 6 hours
                            unk10, cmd, ctr = struct.unpack(">BBB", pkt[17:20])
                            packet_str += "len={0:02x} {1:02x} cmd={2:02x} ctr={3:02x}".format(l4, unk10, cmd, ctr)
                            packet_str += to_hex(pkt[20:])
                            # TODO: Parse the rest
                        elif cmd == 0x28: # just an acknowledgement
                            unk10, cmd, ctr = struct.unpack(">BBB", pkt[17:20])
                            packet_str += "len={0:02x} {1:02x} cmd={2:02x} ctr={3:02x}".format(l4, unk10, cmd, ctr)
                            packet_str += to_hex(pkt[20:])
                        elif cmd == 0x6a:
                            unk10, cmd, ctr = struct.unpack(">BBB", pkt[17:20])
                            packet_str += "len={0:02x} {1:02x} cmd={2:02x} ctr={3:02x}".format(l4, unk10, cmd, ctr)
                            packet_str += to_hex(pkt[20:])
                            # TODO: Parse the rest
                        else:
                            todo_pkt = to_hex(pkt[16:])
                            log.warning('Unable to decode %s' % todo_pkt)
                            packet_str += "todo=" + to_hex(pkt[16:])
                            # TODO: Investigate these
                    else:
                        packet_str += "len={0:02x}".format(l4) + " data=" + to_hex(pkt[17:])
                else:
                    packet_str += "weird=" + to_hex(pkt[16:]) # this happens from time to time
        log.debug(packet_str)


if len(sys.argv) < 2:
    sys.stderr.write("Usage: decode_pcap.py input_file...\n");
    sys.exit(1)

for filename in sys.argv[1:]:
    f = open(filename,"rb")
    magic = f.read(4)

    if magic == "\xa1\xb2\xc3\xd4": #big endian
        endian = ">"
    elif  magic == "\xd4\xc3\xb2\xa1": #little endian
        endian = "<"
    else:
        raise Exception("Not a pcap capture file (bad magic)")
    hdr = f.read(20)
    if len(hdr)<20:
        raise Exception("Invalid pcap file (too short)")
    vermaj,vermin,tz,sig,snaplen,linktype = struct.unpack(endian+"HHIIII",hdr)

    packets = {}
    while True:
        hdr = f.read(16)
        if len(hdr) < 16:
            break
        sec,usec,caplen,wirelen = struct.unpack(endian+"IIII", hdr)
        pkt = f.read(caplen)
        decode_pkt(sec + usec / 1000000., pkt)

for meter in sorted(meter_readings.keys()):
    log.info("Readings for LAN ID " + str(meter) + ":")
    if meter_first_hour[meter] > meter_last_hour[meter]:
        meter_last_hour[meter] += 65536
    meter_readings_str = ''
    for hour in range(meter_first_hour[meter], meter_last_hour[meter] + 1):
        meter_readings_str += ("{0:5.2f}".format(meter_readings[meter][hour % 65536] / 100.0) if meter_readings[meter][hour % 65536] >= 0 else "   ? ")
    log.info(meter_readings_str)


import pygraphviz

G = pygraphviz.AGraph(directed=True, ranksep=2.0, rankdir="RL")

for meter, parent in meter_parents.iteritems():
    meter_name = "{0:08x}".format(meter)
    parent_name = "{0:08x}".format(parent)
    if parent & 0x80000000:
        G.add_node(parent_name, color="red", rank="max")
    G.add_edge(meter_name, parent_name)

    if (meter_levels[parent] >= 2) and (parent not in meter_parents):
        gatekeeper_name = "{0:08x}".format(meter_gatekeepers[meter])

        G.add_node(gatekeeper_name, color="red", rank="max")
        G.add_node("Level 1\n(" + gatekeeper_name + ")", color="gray")
        G.add_edge("Level 1\n(" + gatekeeper_name + ")", gatekeeper_name)
        for x in range(1, meter_levels[parent] - 1):
            G.add_node("Level " + str(x+1) + "\n(" + gatekeeper_name + ")", color="gray")
            G.add_edge("Level " + str(x+1) + "\n(" + gatekeeper_name + ")", "Level " + str(x) + "\n(" + gatekeeper_name + ")")
        G.add_edge(parent_name, "Level " + str(meter_levels[parent] - 1) + "\n(" + gatekeeper_name + ")")

G.layout(prog="dot")
G.draw("mesh.pdf")
