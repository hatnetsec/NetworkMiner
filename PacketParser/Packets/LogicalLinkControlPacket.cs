//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //Logical Link Control
    //http://tools.ietf.org/html/rfc1042
    public class LogicalLinkControlPacket : AbstractPacket {

        //http://www.rhyshaden.com/eth_intr.htm
        //http://www.cadvision.com/blanchas/Intro2dcRev2/page134.html
        public enum ServiceAccessPointType : byte { NullLsap=0x00, SpanningTree=0x42, X_25overIEEE802_2=0x7e, SubNetworkAccessProtocol=0xaa, IbmNetBIOS=0xf0, HpExtendedLLC=0xf8, ISONetworkLayerProtocol=0xfe }


        private byte dsap, ssap, control;
        private uint organisationCode;
        private ushort etherType;

        internal LogicalLinkControlPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Logical Link Control (LLC)") {
            this.dsap=parentFrame.Data[packetStartIndex];
            this.ssap=parentFrame.Data[packetStartIndex+1];
            this.control=parentFrame.Data[packetStartIndex+2];

            //check for 802.2 SNAP protocol
            if(this.dsap==(byte)ServiceAccessPointType.SubNetworkAccessProtocol) {
                this.organisationCode = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 3) >> 8;
                this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("EtherType", "0x"+etherType.ToString("X2"));
            }
            else if(this.dsap==(byte)ServiceAccessPointType.HpExtendedLLC){
                this.etherType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("EtherType", "0x"+etherType.ToString("X2"));
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            AbstractPacket packet=null;
            try {
                if(this.dsap==(byte)ServiceAccessPointType.SubNetworkAccessProtocol) {
                    if(PacketStartIndex+8<PacketEndIndex) {
                        if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.IPv4) {//IPv4
                            packet=new IPv4Packet(this.ParentFrame, PacketStartIndex+8, PacketEndIndex);
                        }
                        else if(this.etherType==(ushort)Ethernet2Packet.EtherTypes.ARP) {//ARP
                            //packet=new Ethernet2Packet(this.ParentFrame, PacketStartIndex+8, PacketEndIndex);
                            packet=new ArpPacket(this.ParentFrame, PacketStartIndex+8, PacketEndIndex);
                        }
                        else {
                            packet=new RawPacket(this.ParentFrame, PacketStartIndex+8, PacketEndIndex);
                        }
                    }
                }
                else if(this.dsap==(byte)ServiceAccessPointType.HpExtendedLLC && this.etherType==(ushort)Ethernet2Packet.EtherTypes.HPSW){
                    if(PacketStartIndex+10<PacketEndIndex){
                        //skip HP Extended LLC positions...
                        packet=new HpSwitchProtocolPacket(this.ParentFrame, PacketStartIndex+3+3+2+2, PacketEndIndex);
                    }
                }
                else {//Not 802.2 SNAP or HPSW
                    if(PacketStartIndex+3<PacketEndIndex) {
                        packet=new RawPacket(this.ParentFrame, PacketStartIndex+3, PacketEndIndex);
                    }
                }
            }
            catch(Exception e) {
                //packet=new RawPacket(this.ParentFrame, PacketStartIndex+14, PacketEndIndex);
                packet=new RawPacket(this.ParentFrame, PacketStartIndex+3, PacketEndIndex);
            }
            if(packet!=null){
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
