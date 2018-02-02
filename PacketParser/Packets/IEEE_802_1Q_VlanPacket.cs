using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class IEEE_802_1Q_VlanPacket : AbstractPacket {

        //http://en.wikipedia.org/wiki/IEEE_802.1Q
        //vlan1.pcap
        //pcapr: dd5ad490-9804-012b-b2a6-0016cb8cea27.cap

        private byte priorityTag;//only 3 bits. http://www.networkworld.com/details/475.html
        private ushort vlanID;//only 12 bits
        private ushort etherType;

        public ushort VlanID { get { return this.vlanID; } }

        internal IEEE_802_1Q_VlanPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "802.1Q VLAN") {
            this.priorityTag=(byte)(parentFrame.Data[packetEndIndex]>>5);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Priority", priorityTag.ToString());
            this.vlanID = (ushort)(Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex, false) & 0x0fff);//mask away the first nibble
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("VLAN ID", vlanID.ToString());

            //this ushort is sometimes the length rather than the etherType
            this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 2, false);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //same as for Ethernet's GetSubPackets()
            if(PacketStartIndex+4<PacketEndIndex) {
                AbstractPacket packet;
                /*
                if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.IPv4) {
                    //IPv4 packet
                    packet=new IPv4Packet(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.ARP) {
                    packet=new ArpPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                    //ARP-packet
                }
                else {
                    //something else
                    packet=new RawPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }*/

                //copied from Ethernet2Packet.cs
                if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.IPv4) {
                    //IPv4 packet
                    packet=new IPv4Packet(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.IPv6) {
                    //IPv6 packet
                    packet=new IPv6Packet(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                //else if(this.ParentFrame.Data[PacketStartIndex+12]==0x08 && this.ParentFrame.Data[PacketStartIndex+13]==0x06) {
                else if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.ARP) {
                    packet=new ArpPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                    //ARP-packet
                }
                else if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.IEEE802_1Q) {
                    //VLAN
                    packet=new IEEE_802_1Q_VlanPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else if (this.etherType == (ushort)Ethernet2Packet.EtherTypes.PPPoE) {
                    packet = new PointToPointOverEthernetPacket(ParentFrame, PacketStartIndex + 4, PacketEndIndex);
                }
                //etherType might actually be a content length if it is an IEEE 802.3 packet
                else if(this.etherType<0x0600) {
                    //the etherType showed to actually be a length value
                    packet=new LogicalLinkControlPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                else {
                    //something else
                    packet=new RawPacket(this.ParentFrame, PacketStartIndex+4, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
