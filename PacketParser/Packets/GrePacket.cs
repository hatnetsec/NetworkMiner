using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class GrePacket : AbstractPacket {

        //http://www.faqs.org/rfcs/rfc2784.html
        //http://www.faqs.org/rfcs/rfc1701.html

        private const int PACKET_LENGTH = 4;//4 bytes fixed length

        private ushort etherType;
        

        internal GrePacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "GRE") {
            //first 4 bytes of flag data

            //then etherType
            this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            AbstractPacket packet = Ethernet2Packet.GetPacketForType(this.etherType, this.ParentFrame, this.PacketStartIndex + PACKET_LENGTH, this.PacketEndIndex);
            yield return packet;
            foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                yield return subPacket;
        }
    }
}
