using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class NullLoopbackPacket : AbstractPacket {

        //http://wiki.wireshark.org/NullLoopback


        public enum ProtocolFamily : uint {
            AF_INET = 2,//IPv4
            AF_INET6_OpenBSD = 24,//NetBSD,OpenBSD,BSD/OS
            AF_INET6_FreeBSD = 28,//FreeBSD,DragonFlyBSD
            AF_INET6_OSX = 30//Darwin/Mac OS X
        }

        private const int PACKET_LENGTH = 4; //4 bytes

        private uint protocolFamily;

        internal NullLoopbackPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Null/Loopback") {
                this.protocolFamily = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex, 4, true);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            AbstractPacket packet = null;
            if (this.protocolFamily == (uint)ProtocolFamily.AF_INET)
                packet = new IPv4Packet(this.ParentFrame, this.PacketStartIndex + PACKET_LENGTH, this.PacketEndIndex);
            else if (this.protocolFamily == (uint)ProtocolFamily.AF_INET6_OpenBSD)
                packet = new IPv6Packet(this.ParentFrame, this.PacketStartIndex + PACKET_LENGTH, this.PacketEndIndex);
            else if (this.protocolFamily == (uint)ProtocolFamily.AF_INET6_FreeBSD)
                packet = new IPv6Packet(this.ParentFrame, this.PacketStartIndex + PACKET_LENGTH, this.PacketEndIndex);
            else if (this.protocolFamily == (uint)ProtocolFamily.AF_INET6_OSX)
                packet = new IPv6Packet(this.ParentFrame, this.PacketStartIndex + PACKET_LENGTH, this.PacketEndIndex);

            if (packet == null)
                yield break;
            else
                yield return packet;
            foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                yield return subPacket;
        }
    }
}
