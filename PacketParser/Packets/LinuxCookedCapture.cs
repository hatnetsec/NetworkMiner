using System;
using System.Collections.Generic;
using System.Text;
using System.Net.NetworkInformation;

namespace PacketParser.Packets {
    public class LinuxCookedCapture : AbstractPacket{

        /**
         * LINUX_SLL_HOST="Unicast to us"
         * LINUX_SLL_BROADCAST="Broadcast"
         * LINUX_SLL_MULTICAST="Multicast"
         * LINUX_SLL_OTHERHOST="Unicast to another host"
         * LINUX_SLL_OUTGOING="Sent by us"
         **/
        internal enum PacketTypes : ushort { LINUX_SLL_HOST=0, LINUX_SLL_BROADCAST=1, LINUX_SLL_MULTICAST=2, LINUX_SLL_OTHERHOST=3, LINUX_SLL_OUTGOING=4};

        private ushort packetType;
        private ushort addressType;
        private ushort addressLength;
        //source
        private PhysicalAddress sourceMacAddress;
        private ushort protocol;


        public LinuxCookedCapture(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Linux cooked capture (SLL)") {

            this.packetType = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex);

            if (!this.ParentFrame.QuickParse) {
                if (this.packetType == (ushort)PacketTypes.LINUX_SLL_HOST) {
                    this.Attributes.Add("Packet Type", "Unicast to us (HOST)");
                }
                else if (this.packetType == (ushort)PacketTypes.LINUX_SLL_BROADCAST) {
                    this.Attributes.Add("Packet Type", "Broadcast");
                }
                else if (this.packetType == (ushort)PacketTypes.LINUX_SLL_MULTICAST) {
                    this.Attributes.Add("Packet Type", "Multicast");
                }
                else if (this.packetType == (ushort)PacketTypes.LINUX_SLL_OTHERHOST) {
                    this.Attributes.Add("Packet Type", "Unicast to another host (OTHERHOST)");
                }
                else if (this.packetType == (ushort)PacketTypes.LINUX_SLL_OUTGOING) {
                    this.Attributes.Add("Packet Type", "Sent by us (OUTGOING)");
                }
            }

            this.addressType = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 2);
            this.addressLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 4);
            if(addressLength==6) {//ethernet
                byte[] tmpSourceMAC=new byte[6];
                Array.Copy(parentFrame.Data, packetStartIndex+6, tmpSourceMAC, 0, tmpSourceMAC.Length);
                this.sourceMacAddress=new PhysicalAddress(tmpSourceMAC);
            }
            else {
                this.sourceMacAddress=PhysicalAddress.None;
            }

            this.protocol = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 14);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //same as for Ethernet2Packet.cs

            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+16<PacketEndIndex) {
                AbstractPacket packet;
                if(this.protocol==(ushort)Ethernet2Packet.EtherTypes.IPv4) {
                    //IPv4 packet
                    packet=new IPv4Packet(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                }
                else if(this.protocol==(ushort)Ethernet2Packet.EtherTypes.IPv6) {
                    //IPv6 packet
                    packet=new IPv6Packet(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                }
                //else if(this.ParentFrame.Data[PacketStartIndex+12]==0x08 && this.ParentFrame.Data[PacketStartIndex+13]==0x06) {
                else if(this.protocol==(ushort)Ethernet2Packet.EtherTypes.ARP) {
                    packet=new ArpPacket(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                    //ARP-packet
                }
                else if(this.protocol==(ushort)Ethernet2Packet.EtherTypes.IEEE802_1Q) {
                    //VLAN
                    packet=new IEEE_802_1Q_VlanPacket(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                }
                else if (this.protocol == (ushort)Ethernet2Packet.EtherTypes.PPPoE) {
                    packet = new PointToPointOverEthernetPacket(this.ParentFrame, PacketStartIndex + 16, PacketEndIndex);
                }
                //etherType might actually be a content length if it is an IEEE 802.3 packet
                else if(this.protocol<0x0600) {
                    //the etherType showed to actually be a length value
                    packet=new LogicalLinkControlPacket(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                }
                else {
                    //something else
                    packet=new RawPacket(this.ParentFrame, PacketStartIndex+16, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

        }
    }
}
