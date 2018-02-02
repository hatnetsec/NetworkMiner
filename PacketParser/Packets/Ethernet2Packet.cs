//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Net.NetworkInformation;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/Ethernet
    //http://en.wikipedia.org/wiki/DIX
    public class Ethernet2Packet : AbstractPacket {
        //http://en.wikipedia.org/wiki/Ethertype
        internal enum EtherTypes : ushort {
            IEEE802_3_Max = 0x0600,
            HPSW =          0x0623,
            IPv4 =          0x0800,
            ARP =           0x0806,
            IEEE802_1Q =    0x8100,
            IPv6 =          0x86dd,
            MPLS =          0x8847,
            PPPoE =         0x8864
        };


        internal static AbstractPacket GetPacketForType(ushort etherType, Frame parentFrame, int newPacketStartIndex, int newPacketEndIndex) {
            AbstractPacket packet;

            try {
                //if(this.ParentFrame.Data[PacketStartIndex+12]==0x08 && this.ParentFrame.Data[PacketStartIndex+13]==0x00) {
                if (etherType == (ushort)Ethernet2Packet.EtherTypes.IPv4) {
                    //IPv4 packet
                    packet = new IPv4Packet(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
                else if (etherType == (ushort)Ethernet2Packet.EtherTypes.IPv6) {
                    //IPv6 packet
                    packet = new IPv6Packet(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
                //else if(this.ParentFrame.Data[PacketStartIndex+12]==0x08 && this.ParentFrame.Data[PacketStartIndex+13]==0x06) {
                else if (etherType == (ushort)Ethernet2Packet.EtherTypes.ARP) {
                    packet = new ArpPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
                    //ARP-packet
                }
                else if (etherType == (ushort)Ethernet2Packet.EtherTypes.IEEE802_1Q) {
                    //VLAN
                    packet = new IEEE_802_1Q_VlanPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
                else if (etherType == (ushort)Ethernet2Packet.EtherTypes.MPLS) {
                    packet = new Mpls(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
                else if (etherType == (ushort)Ethernet2Packet.EtherTypes.PPPoE) {
                    packet = new PointToPointOverEthernetPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
                //etherType might actually be a content length if it is an IEEE 802.3 packet
                else if (etherType < 0x0600) {
                    //the etherType showed to actually be a length value
                    packet = new LogicalLinkControlPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }

                else {
                    //something else
                    packet = new RawPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
                }
            }
            catch (Exception) {
                packet = new RawPacket(parentFrame, newPacketStartIndex, newPacketEndIndex);
            }
            return packet;
        }

        PhysicalAddress sourceMAC, destinationMAC;

        ushort etherType;// (must be larger than 0x0600, otherwise Ether v.1) 0x0800 = IP, 0x0806 = ARP



        public PhysicalAddress SourceMACAddress { get { return this.sourceMAC; } }//OBS: Source och desination verkar ha bytt plats!!!
        public PhysicalAddress DestinationMACAddress { get { return this.destinationMAC; } }



        
        internal Ethernet2Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Ethernet2") {

            this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12);

            byte[] tmpDestinationMAC=new byte[6];
            Array.Copy(parentFrame.Data, packetStartIndex, tmpDestinationMAC, 0, tmpDestinationMAC.Length);
            this.destinationMAC=new PhysicalAddress(tmpDestinationMAC);

            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination MAC", this.destinationMAC.ToString());

            byte[] tmpSourceMAC=new byte[6];
            Array.Copy(parentFrame.Data, packetStartIndex+6, tmpSourceMAC, 0, tmpSourceMAC.Length);
            this.sourceMAC=new PhysicalAddress(tmpSourceMAC);

            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source MAC", this.sourceMAC.ToString());
        }

        private string ConvertToHexString(byte[] data) {
            StringBuilder str=new StringBuilder();
            for(int i=0; i<data.Length-1; i++) {
                str.Append(data[i].ToString("X2")+"-");
            }
            str.Append(data[data.Length-1].ToString("X2"));
            return str.ToString();
        }


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+14<PacketEndIndex) {
                AbstractPacket packet = GetPacketForType(this.etherType, this.ParentFrame, this.PacketStartIndex+14, this.PacketEndIndex);
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }

    }
}
