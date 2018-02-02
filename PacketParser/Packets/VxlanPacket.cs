using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class VxlanPacket : AbstractPacket {

        /**
         * https://tools.ietf.org/html/rfc7348
         * VXLAN Header:
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |R|R|R|R|I|R|R|R|            Reserved                           |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |                VXLAN Network Identifier (VNI) |   Reserved    |
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         **/

        /**
         * IANA has assigned the value 4789 for the
        VXLAN UDP port, and this value SHOULD be used by default as the
        destination UDP port.  Some early implementations of VXLAN have
        used other values for the destination port.  To enable
        interoperability with these implementations, the destination
        port SHOULD be configurable.
            */

        private int vxlanNetworkIdentifier = -1;
        private Ethernet2Packet innerEthernetPacket = null;

        internal VxlanPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
        : base(parentFrame, packetStartIndex, packetEndIndex, "VXLAN") {
            if (packetEndIndex >= packetStartIndex + 16) {
                this.vxlanNetworkIdentifier = (int)Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4, 3);
            }
        }



        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;

        if (this.innerEthernetPacket != null)
            yield return this.innerEthernetPacket;
        else if(this.vxlanNetworkIdentifier >= 0) {
            this.innerEthernetPacket = new Ethernet2Packet(base.ParentFrame, base.PacketStartIndex + 8, base.PacketEndIndex);
            yield return this.innerEthernetPacket;
            foreach (AbstractPacket subPacket in this.innerEthernetPacket.GetSubPackets(false))
                yield return subPacket;
            }
        else
            yield break;
        }
    }
}
