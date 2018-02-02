using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class CiscoHdlcPacket : AbstractPacket{
        private ushort? protocolCode;


        internal CiscoHdlcPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Cisco HDLC") {
            //skip address and control

            //make sure the 4 first bytes are available
            if(packetStartIndex+4<=parentFrame.Data.Length && packetStartIndex+3<=packetEndIndex) {
                this.protocolCode = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            }
            else
                this.protocolCode=null;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+4<PacketEndIndex && this.protocolCode!=null) {//there is room for data
                AbstractPacket packet;
                //check the protocolCode
                if(this.protocolCode.Value==(ushort)Ethernet2Packet.EtherTypes.IPv4) {
                    packet=new IPv4Packet(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if(this.protocolCode.Value==(ushort)Ethernet2Packet.EtherTypes.IPv6) {
                    packet=new IPv6Packet(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if(this.protocolCode.Value==(ushort)Ethernet2Packet.EtherTypes.ARP) {//not sure if ARP packets are used inside cHDLC frames
                    packet=new ArpPacket(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if (this.protocolCode.Value == (ushort)Ethernet2Packet.EtherTypes.IEEE802_1Q) {
                    //VLAN
                    packet = new IEEE_802_1Q_VlanPacket(ParentFrame, PacketStartIndex + 4, PacketEndIndex);
                }
                else if (this.protocolCode.Value == (ushort)Ethernet2Packet.EtherTypes.PPPoE) {
                    packet = new PointToPointOverEthernetPacket(ParentFrame, PacketStartIndex + 4, PacketEndIndex);
                }
                else {
                    //something else
                    packet=new RawPacket(ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
