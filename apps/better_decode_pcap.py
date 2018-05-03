#!/usr/bin/env python

import sys
import struct
from datetime import datetime, timedelta
import logging as log
from construct import StreamError, Construct, Struct, Int8ub, Int16ub, Int32ub, Array

class ParsePcap(object):
    magic_big = "\xa1\xb2\xc3\xd4"
    magic_small = "\xd4\xc3\xb2\xa1"
    magic_length = 4
    header_length = 20
    packet_header_length = 16

    def __init__(self, filename):
        self.filename = filename
        self.fp = None
        self.endian = None

    def __iter__(self):
        return self

    def open_file(self):
        self.fp = open(self.filename, 'rb')
        magic = self.fp.read(self.magic_length)

        if magic == self.magic_big:
            self.endian = '>'
        elif  magic == self.magic_small:
            self.endian = '<'
        else:
            raise Exception("Not a pcap capture file (bad magic)")

        header = self.fp.read(self.header_length)
        if len(header) < self.header_length:
            raise Exception("Invalid pcap file (too short)")
        
        # Unused
        # vermaj, vermin, tz, sig, snaplen, linktype = struct.unpack(self.endian + 'HHIIII', header)


    def next(self):
        if self.fp is None:  # Need to open the file
            self.open_file()

        pkt_header = self.fp.read(self.packet_header_length)
        if len(pkt_header) < self.packet_header_length:  # EOF is reached
            self.fp.close()
            self.fp = None
            self.endian = None
            raise StopIteration

        sec, usec, caplen, wirelen = struct.unpack(self.endian + 'IIII', pkt_header)

        dt = datetime.fromtimestamp(sec) + timedelta(microseconds=usec)
        pkt_data = self.fp.read(caplen)

        return (dt, pkt_data)

class R2SPacket(object):
    class PacketType(object):
        """ Implement an 'enum' """
        Unknown, Malformed, HourlyData = range(3)

    R2S_Header = Struct(
        'l1' / Int8ub,
        'flag1' / Int8ub,
        'src' / Int32ub,
        'dst' / Int32ub,
        Int8ub[3],
        'ts1' / Int8ub,
        'ts2' / Int8ub,
        'ts3' / Int8ub,
    )

    R2S_Metadata = Struct(
        'l4' / Int8ub,
        Int8ub,
        'cmd' / Int8ub,
        'ctr' / Int8ub,
        Int8ub,
        'flag2' / Int8ub,
        'curr_hour' / Int16ub,
        'last_hour' / Int16ub,
        'n_hours' / Int8ub,
    )

    R2S_Usage_Data = Struct(
        'readings' / Array(lambda this: this.n_hours / 2, Int32ub),
    )

    def __init__(self, datetime_obj, packet_data):
        self.datetime_obj = datetime_obj
        self.packet_data = packet_data
        self.packet_type = None
        self.decoded_packet = None

    def __repr__(self):
        if self.packet_type == self.PacketType.Unknown:
            return 'Unknown R2S Data'
        elif self.packet_type == self.PacketType.Malformed:
            return 'Malformed R2S Data'
        elif self.packet_type == self.PacketType.HourlyData:
            return 'Hourly R2S Data {}: {} {} {}'.format(
                self.datetime_obj.strftime('%Y-%m-%d %H:%M:%S:%f'),
                self.decoded_packet.last_hour,
                ', '.join([str(l) for l in self.decoded_packet.readings]),
                self.decoded_packet.curr_hour
            )
        else:
            return None

    def try_to_parse_struct(self, packet_struct):
        try:
            self.decoded_packet = packet_struct.parse(self.packet_data)
        except StreamError as e:
            self.decoded_packet = None

    def parse(self):
        # First try to parse the header
        self.try_to_parse_struct(self.R2S_Header)
        if not self.decoded_packet:  # Check result
            self.packet_type = self.PacketType.Malformed
            return self  # Return early

        if (self.decoded_packet.dst != 0
            and (self.decoded_packet.l1 < 35 or not (self.decoded_packet.src & (0x8 << 28)))):

            self.try_to_parse_struct(self.R2S_Header + self.R2S_Metadata)
            if not self.decoded_packet:  # Check result
                self.packet_type = self.PacketType.Unknown
                return self  # Return early

            if (self.decoded_packet.l4 == self.decoded_packet.l1 - 17
                    and self.decoded_packet.cmd == 0xCE):
                
                self.try_to_parse_struct(self.R2S_Header + self.R2S_Metadata + self.R2S_Usage_Data)
                if not self.decoded_packet:  # Check result
                    self.packet_type = self.PacketType.Unknown
                    return self  # Return early

                self.packet_type = self.PacketType.HourlyData

        return self

log.basicConfig(stream=sys.stdout, level=log.INFO)

def hexrep(raw_string):
    return ''.join([c.encode('hex') for c in raw_string])

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: better_decode_pcap.py input_file...\n");
        sys.exit(1)

    for filename in sys.argv[1:]:
        for (time_data, packet_data) in ParsePcap(filename):
            r2s = R2SPacket(time_data, packet_data).parse()

            if r2s.packet_type == R2SPacket.PacketType.HourlyData:
                print r2s
            
