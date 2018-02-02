using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/IPv6
    public class IPv6Packet : AbstractPacket, IIPPacket {

        private ushort payloadLength;
        private byte nextHeader;
        private byte hopLimit;
        private System.Net.IPAddress sourceIP, destinationIP;

        public System.Net.IPAddress SourceIPAddress { get { return this.sourceIP; } }
        public System.Net.IPAddress DestinationIPAddress { get { return destinationIP; } }
        public int PayloadLength { get { return this.payloadLength; } }
        public byte HopLimit { get { return this.hopLimit; } }


        internal IPv6Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IPv6") {

            if (!this.ParentFrame.QuickParse)
                if((parentFrame.Data[packetStartIndex]>>4)!=0x06)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex, "IP Version!=6 ("+(parentFrame.Data[packetStartIndex]>>4)+")"));
            //skip traffic class
            //skip flow label

            //get payload length
            this.payloadLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
            this.nextHeader=parentFrame.Data[PacketStartIndex+6];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Next Header", "0x"+nextHeader.ToString("X2"));
            this.hopLimit=parentFrame.Data[PacketStartIndex+7];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Hop Limit", hopLimit.ToString());

            //source (offset=8)
            byte[] sourceIpBytes=new byte[16];
            Array.Copy(parentFrame.Data, packetStartIndex+8, sourceIpBytes, 0, sourceIpBytes.Length);
            this.sourceIP=new System.Net.IPAddress(sourceIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source IP", sourceIP.ToString());
            //destination (offset=8+16=24)
            byte[] destinationIpBytes=new byte[16];
            Array.Copy(parentFrame.Data, packetStartIndex+24, destinationIpBytes, 0, destinationIpBytes.Length);
            this.destinationIP=new System.Net.IPAddress(destinationIpBytes);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination IP", destinationIP.ToString());

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            if(PacketStartIndex+40<PacketEndIndex) {
                AbstractPacket packet;
                try {
                    if(this.nextHeader==(byte)IPv4Packet.RFC1700Protocols.TCP) {
                        //TCP packet
                        if (PacketStartIndex + 40 + 20 > PacketEndIndex + 1)
                            yield break;//too little room for a TCP packet
                        else
                            packet =new TcpPacket(this.ParentFrame, PacketStartIndex+40, PacketEndIndex);//bugg?                   
                    }
                    else if(this.nextHeader==(byte)IPv4Packet.RFC1700Protocols.UDP) {
                        //UDP packet
                        if (PacketStartIndex + 40 + 8 > PacketEndIndex + 1)
                            yield break;//too little room for a UDP packet
                        else
                            packet =new UdpPacket(this.ParentFrame, PacketStartIndex+40, PacketEndIndex);
                    }
                    else if (this.nextHeader == (byte)IPv4Packet.RFC1700Protocols.SCTP) {
                        //SCTP packet
                        packet = new SctpPacket(this.ParentFrame, PacketStartIndex + 40, PacketEndIndex);
                    }
                    else if (this.nextHeader == (byte)IPv4Packet.RFC1700Protocols.GRE) {
                        //GRE packet
                        packet = new GrePacket(this.ParentFrame, PacketStartIndex + 40, PacketEndIndex);
                    }
                    else {
                        packet=new RawPacket(ParentFrame, PacketStartIndex+40, PacketEndIndex);
                    }
                }
                catch(Exception) {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+40, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }


    }
}
