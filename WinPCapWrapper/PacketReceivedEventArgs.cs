//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkWrapper {
    //public delegate void PacketReceivedHandler(object sender, DateTime timestamp, byte[] data);

    //based on: http://www.codeproject.com/csharp/csevents01.asp
    public class PacketReceivedEventArgs : EventArgs {

        public enum PacketTypes { NullLoopback, Ethernet2Packet, IPv4Packet, IPv6Packet, IEEE_802_11Packet, IEEE_802_11RadiotapPacket, CiscoHDLC, LinuxCookedCapture, PrismCaptureHeader };

        private byte[] data;
        private DateTime timestamp;
        private PacketTypes packetType;

        public DateTime Timestamp { get { return timestamp; } }
        public byte[] Data { get { return data; } }
        public PacketTypes PacketType { get { return packetType; } }

        public PacketReceivedEventArgs(byte[] data, DateTime timestamp/*, int length*/, PacketTypes packetType) {
            this.data=data;
            this.timestamp=timestamp;
            this.packetType=packetType;
        }

    }

    public delegate void PacketReceivedHandler(object sender, PacketReceivedEventArgs e);

}
