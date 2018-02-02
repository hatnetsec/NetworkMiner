//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/IPv4
    //http://www.ietf.org/rfc/rfc791.txt
    public class IPv4Packet : AbstractPacket, IIPPacket {

        //http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
        //http://www.faqs.org/rfcs/rfc1700.html
        internal enum RFC1700Protocols : byte { ICMP=0x01, IGMP=0x02, TCP=0x06, UDP=0x11, IPv6=0x29, GRE=0x2f, OSPF=0x59, SCTP=0x84};

        private const ushort FRAGMENT_OFFSET_MASK = 0x1fff; //13 bytes

        //byte[] sourceMAC, destinationMAC;
        private System.Net.IPAddress sourceIP, destinationIP;
        private bool dontFragmentFlag;
        private bool moreFragmentsFlag;
        private ushort fragmentOffset;
        private ushort identification;//IPID
        private byte timeToLive;
        private byte protocol;
        private byte headerLength;
        private ushort totalLength;

        //lägg till checksum!


        public System.Net.IPAddress SourceIPAddress { get { return sourceIP; } }
        public System.Net.IPAddress DestinationIPAddress {get{return destinationIP;}}
        public byte HeaderLength { get { return headerLength; } }
        public ushort TotalLength { get { return totalLength; } }
        public int PayloadLength { get { return this.totalLength - this.headerLength; } }
        public bool DontFragmentFlag { get { return dontFragmentFlag; } }//needed for OS fingerprinting
        public byte TimeToLive { get { return timeToLive; } }//needed for OS fingerprinting
        public byte HopLimit { get { return this.TimeToLive; } }

        internal IPv4Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "IPv4") {
            //version = 4 (offset 0)
            if((parentFrame.Data[packetStartIndex]>>4)!=0x04)
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex, "IP Version!=4 ("+(parentFrame.Data[packetStartIndex]>>4)+")"));

                //Internet Header Length (IHL)  (offset=0,5)
            this.headerLength=(byte)(4*(parentFrame.Data[packetStartIndex]&(byte)0x0F));
            if (!this.ParentFrame.QuickParse) {
                if (headerLength < 20)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex, "Too short defined IPv4 field HeaderLength"));
                else if (packetStartIndex + headerLength > packetEndIndex + 1)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex, "Too long defined IPv4 field HeaderLength"));
            }
            //Total Length (offset=2)
            this.totalLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Total Length", totalLength.ToString());

            if(this.totalLength !=packetEndIndex-packetStartIndex+1) {
                //total length can be set to 0x0000 when using TCP Segment Offload (TSO).
                //I sometimes see this on network running jumbo frames, only when frame size > 1500
                if (this.totalLength == 0)//TCP Segment Offload suspected
                    this.totalLength = (ushort)(packetEndIndex - packetStartIndex + 1);
                else if (this.totalLength <packetEndIndex-packetStartIndex+1)//the ethernet packet has to be at least 60 bytes. so there might be some padding (ethernet trailer) here http://mirror.ethereal.com/lists/ethereal-users/200012/msg00114.html
                    base.PacketEndIndex=packetStartIndex+ this.totalLength -1;//adjust the IPv4 packet length since it shall be shorter
            }
            //IPID (offset=4)
            this.identification = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4, false);

            //Flags (offset=6) + Fragment offset
            this.dontFragmentFlag=((parentFrame.Data[packetStartIndex+6]&0x40)==0x40);
            this.moreFragmentsFlag=((parentFrame.Data[packetStartIndex+6]&0x20)==0x20);
            this.fragmentOffset = (ushort)((Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex+6, false) & FRAGMENT_OFFSET_MASK) << 3); //The fragment offset field, measured in units of eight-byte blocks, is 13 bits long and specifies the offset of a particular fragment relative to the beginning of the original unfragmented IP datagram.

            //this.Attributes.Add("Total Length3", (packetEndIndex-packetStartIndex+1).ToString());
            //TTL (offset=8)
            this.timeToLive=parentFrame.Data[packetStartIndex+8];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("TTL", timeToLive.ToString());
            
            this.protocol=parentFrame.Data[packetStartIndex+9];
            //source (offset=12)
            byte[] sourceIpBytes=new byte[4];
            Array.Copy(parentFrame.Data, packetStartIndex+12, sourceIpBytes, 0, sourceIpBytes.Length);
            this.sourceIP=new System.Net.IPAddress(sourceIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source IP", sourceIP.ToString());
            //destination (offset=16)
            byte[] destinationIpBytes=new byte[4];
            Array.Copy(parentFrame.Data, packetStartIndex+16, destinationIpBytes, 0, destinationIpBytes.Length);
            this.destinationIP=new System.Net.IPAddress(destinationIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination IP", destinationIP.ToString());
        }



        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if (this.fragmentOffset != 0 || this.moreFragmentsFlag) {
                if (!this.ParentFrame.QuickParse) {
                    byte[] reassembledIpFrameData = null;
                    string fragmentID = this.GetFragmentIdentifier();
                    lock (PacketHandler.Ipv4Fragments) {
                        List<IPv4Packet> ipPacketList;
                        if (!PacketHandler.Ipv4Fragments.ContainsKey(fragmentID)) {
                            ipPacketList = new List<IPv4Packet>();
                            PacketHandler.Ipv4Fragments.Add(fragmentID, ipPacketList);
                        }
                        else {
                            ipPacketList = PacketHandler.Ipv4Fragments[fragmentID];
                        }
                        ipPacketList.Add(this);
                        //see if we have all fragments of a complete IP packet
                        bool allFragmentsHaveMoreFragmentsFlag = true;
                        int completeIpPacketPayloadLength = 0;
                        foreach (IPv4Packet p in ipPacketList) {
                            completeIpPacketPayloadLength += p.PayloadLength;
                            if (!p.moreFragmentsFlag)
                                allFragmentsHaveMoreFragmentsFlag = false;
                        }
                        if (!allFragmentsHaveMoreFragmentsFlag) {
                            //we might actually have all the fragments!
                            reassembledIpFrameData = new byte[this.HeaderLength + completeIpPacketPayloadLength];
                            if (reassembledIpFrameData.Length > UInt16.MaxValue) {
                                PacketHandler.Ipv4Fragments.Remove(fragmentID);
                                yield break;
                            }

                            foreach (IPv4Packet p in ipPacketList) {
                                if (p.fragmentOffset + this.HeaderLength + p.PayloadLength > reassembledIpFrameData.Length) {
                                    yield break;
                                }
                                Array.Copy(p.ParentFrame.Data, p.PacketStartIndex + p.HeaderLength, reassembledIpFrameData, p.fragmentOffset + this.HeaderLength, p.PayloadLength);
                            }
                            PacketHandler.Ipv4Fragments.Remove(fragmentID);//we don't want to reassemble this IP frame any more
                            //we now need to create a fake frame and run GetSubPackets(false) on it
                        }
                    }//Release lock on PacketHandler.Ipv4Fragments
                    if(reassembledIpFrameData != null && reassembledIpFrameData.Length > this.HeaderLength) {
                        Array.Copy(this.ParentFrame.Data, this.PacketStartIndex, reassembledIpFrameData, 0, this.headerLength);

                        //totalLength = (ushort)reassembledIpFrameData.Length;
                        Utils.ByteConverter.ToByteArray((ushort)reassembledIpFrameData.Length, reassembledIpFrameData, 2);
                        //moreFragmentsFlag = false;
                        //fragmentOffset = 0;
                        reassembledIpFrameData[6] = 0;
                        reassembledIpFrameData[7] = 0;



                        Frame reassembledFrame = new Frame(this.ParentFrame.Timestamp, reassembledIpFrameData, ParentFrame.FrameNumber);
                        IPv4Packet reassembledIpPacket = new IPv4Packet(reassembledFrame, 0, reassembledFrame.Data.Length - 1);
                        reassembledIpPacket.fragmentOffset = 0;
                        reassembledIpPacket.moreFragmentsFlag = false;
                        reassembledIpPacket.totalLength = (ushort)reassembledIpFrameData.Length;

                        foreach (AbstractPacket subPacket in reassembledIpPacket.GetSubPackets(false))
                            yield return subPacket;
                    }
                }
            }
            else if(PacketStartIndex+headerLength<PacketEndIndex && this.fragmentOffset == 0) {
                AbstractPacket packet;
                try {
                    if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.TCP) {
                        //TCP packet
                        if (PacketStartIndex + headerLength + 20 > PacketEndIndex + 1)
                            yield break;//too little room for a TCP packet
                        else
                            packet = new TcpPacket(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.UDP) {
                        //UDP packet
                        if (PacketStartIndex + headerLength + 8 > PacketEndIndex + 1)
                            yield break;//too little room for a UDP packet
                        else
                            packet = new UdpPacket(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.SCTP) {
                        //SCTP packet
                        packet = new SctpPacket(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.IPv6) {
                        packet = new IPv6Packet(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.GRE) {
                        packet = new GrePacket(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else if (this.protocol == (byte)IPv4Packet.RFC1700Protocols.ICMP) {
                        packet = new IcmpPacket(this.ParentFrame, PacketStartIndex + headerLength, PacketEndIndex);
                    }
                    else {
                        packet=new RawPacket(ParentFrame, PacketStartIndex+headerLength, PacketEndIndex);
                    }
                }
                catch(Exception) {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+headerLength, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }


        /// <summary>
        /// Builds a string based on sourceIP, destinationIP and IPID
        /// </summary>
        /// <returns></returns>
        internal string GetFragmentIdentifier() {
            return sourceIP.ToString() + "\t" + destinationIP.ToString() + "\t" + this.identification.ToString();
        }


    }
}
