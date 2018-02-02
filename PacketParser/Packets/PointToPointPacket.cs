using System;
using System.Collections.Generic;
using System.Text;
using System.Net.NetworkInformation;

namespace PacketParser.Packets {
    public class PointToPointPacket : AbstractPacket{
        //http://www.rfc-editor.org/rfc/rfc1661.txt The Point-to-Point Protocol (PPP)
        //http://www.rfc-editor.org/rfc/rfc1662.txt PPP in HDLC-like Framing

        private const byte ALL_STATIONS_ADDRESS = 0xff;
        private const byte UNNUMBERED_INFORMATION_COMMAND = 0x03;
        private const ushort IP_PROTOCOL_ID = 0x0021; //http://technet.microsoft.com/en-us/library/cc957975.aspx
        

        private ushort protocol;
        private int protocolStartOffset = 4;

        public PointToPointPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Point-to-Point Protocol (PPP)") {

                if (parentFrame.Data[packetStartIndex] == ALL_STATIONS_ADDRESS) {
                    //PPP in HDLC-like Framing
                    if (packetStartIndex + 3 > packetEndIndex)
                        throw new Exception("Too short PPP header");
                    byte address = parentFrame.Data[packetStartIndex];
                    byte control = parentFrame.Data[packetStartIndex + 1];

                    if (address != ALL_STATIONS_ADDRESS || control != UNNUMBERED_INFORMATION_COMMAND)
                        throw new Exception("Invalid PPP HDLC framing");

                    this.protocol = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, false);
                    this.protocolStartOffset = 4;
                    if (!this.ParentFrame.QuickParse)
                        this.Attributes.Add("Encapsulated protocol", "0x" + this.protocol.ToString("X4"));
                }
                else {
                    //Normal Point-to-Point Protocol (PPP)
                    if (packetStartIndex + 1 > packetEndIndex)
                        throw new Exception("Too short PPP header");
                    this.protocol = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex, false);
                    this.protocolStartOffset = 2;
                }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //same as for Ethernet2Packet.cs

            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+this.protocolStartOffset<PacketEndIndex) {
                AbstractPacket packet;
                if(this.protocol==IP_PROTOCOL_ID) {
                    //IPv4 packet
                    packet = new IPv4Packet(this.ParentFrame, PacketStartIndex + this.protocolStartOffset, PacketEndIndex);
                }
                else {
                    //something else
                    packet = new RawPacket(this.ParentFrame, PacketStartIndex + this.protocolStartOffset, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

        }
    }
}
