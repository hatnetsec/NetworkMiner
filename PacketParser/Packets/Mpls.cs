using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class Mpls : AbstractPacket {


        private const int PAYLOAD_OFFSET = 4;

        
        //private ushort payloadLength;
        private bool bottomOfStack;
        private uint label;

        public Mpls(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "MPLS") {
            this.bottomOfStack = ((parentFrame.Data[packetStartIndex + 2] & 0x01) == 0x01);
            this.label = (Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex) >> 12);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Label", this.label.ToString() + " (0x"+this.label.ToString("X4")+")");
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            AbstractPacket packet;



            if (this.bottomOfStack) {

                /**
                 * EoMPLS = Ethernet over MPLS
                 * http://www.faqs.org/rfcs/rfc4448.html
                 *   0                   1                   2                   3
                 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 *  |0 0 0 0|   Reserved            |       Sequence Number         |
                 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 *  
                 *  In the above diagram, the first 4 bits MUST be set to 0 to indicate
                 *  PW data.  The rest of the first 16 bits are reserved for future use.
                 *  They MUST be set to 0 when transmitting, and MUST be ignored upon
                 *  receipt.
                 **/

                if (ParentFrame.Data[PacketStartIndex + PAYLOAD_OFFSET] < 0x10)
                    packet = new Ethernet2Packet(this.ParentFrame, PacketStartIndex + PAYLOAD_OFFSET + 4, PacketEndIndex);
                else
                    packet = new IPv4Packet(this.ParentFrame, PacketStartIndex + PAYLOAD_OFFSET, PacketEndIndex);
            }
            else
                packet = new Mpls(this.ParentFrame, PacketStartIndex + PAYLOAD_OFFSET, PacketEndIndex);
            yield return packet;
            foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                yield return subPacket;
        }
    }
}
