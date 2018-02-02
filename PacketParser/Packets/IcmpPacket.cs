//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    /**
     *    0                   1                   2                   3
     *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |     Type      |     Code      |          Checksum             |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |                             unused                            |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     *   |      Internet Header + 64 bits of Original Data Datagram      |
     *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    */
    public class IcmpPacket : AbstractPacket, ITransportLayerPacket {

        private byte type;
        private byte code;
        private ushort checksum;

        public ushort SourcePort { get { return 0; } }
        public ushort DestinationPort { get { return 0; } }
        public byte DataOffsetByteCount { get { return 8; } }
        public byte FlagsRaw { get { return type; } }

        internal IcmpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "ICMP") {
            this.type = parentFrame.Data[packetStartIndex];
            this.code = parentFrame.Data[packetStartIndex + 1];
            this.checksum = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            //List<Packet> subPackets=new List<Packet>();
            /*
            if(PacketStartIndex+8<PacketEndIndex) {
                AbstractPacket packet;
                if(false) {
                    packet = null;
                }
                else {
                    packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                }
                if (packet != null) {
                    yield return packet;
                    foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
            }
            */
        }


        
    }
}
