using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class PointToPointOverEthernetPacket : AbstractPacket {
        //http://tools.ietf.org/html/rfc2516

        /**
         *      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     |  VER  | TYPE  |      CODE     |          SESSION_ID           |
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     |            LENGTH             |           payload             ~
         *     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         *     
         * The VER field is four bits and MUST be set to 0x1 for this version of the PPPoE specification.
         * 
         * The TYPE field is four bits and MUST be set to 0x1 for this version of the PPPoE specification.
         * 
         **/

        private const int PAYLOAD_OFFSET = 6;

        private byte code;
        private ushort payloadLength;

        private enum CODE : byte {
            SessionData = 0x00,
            ActiveDiscoveryOffer = 0x07,
            ActiveDiscoveryInitiation = 0x09,
            ActiveDiscoveryRequest = 0x19,
            ActiveDiscoverySessionConfirmation = 0x65,
            ActiveDiscoveryTerminate = 0xa7
        }

        public PointToPointOverEthernetPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Point-to-point protocol over Ethernet (PPPoE)") {
            if (parentFrame.Data[packetStartIndex] != 0x11)
                throw new Exception("Invalid PPPoE Version or Type");
            this.code = parentFrame.Data[packetStartIndex + 1];
            if (this.code == (byte)CODE.SessionData) {
                this.payloadLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
            }

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if (this.payloadLength > 0 && this.code == (byte)CODE.SessionData) {
                int pppEndIndex = this.PacketStartIndex + PAYLOAD_OFFSET + this.payloadLength - 1;
                if (pppEndIndex <= this.PacketEndIndex) {
                    PointToPointPacket packet = new PointToPointPacket(this.ParentFrame, this.PacketStartIndex + PAYLOAD_OFFSET, pppEndIndex);
                    yield return packet;
                    foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                        yield return subPacket;
                }
                
            }
        }
    }
}
