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


    //IEEE 802.11 WLAN
    //http://sss-mag.com/pdf/802_11tut.pdf
    public class IEEE_802_11Packet : AbstractPacket {

        internal class FrameControl {

            private byte versionTypeSubtype, flagData;

            internal byte ProtocolVersion { get { return (byte)(versionTypeSubtype&0x03); } }//2 last bits
            internal byte Type { get { return (byte)((versionTypeSubtype&0x0c)>>2); } }//last 2 but 2 bits
            internal byte SubType { get { return (byte)((versionTypeSubtype&0xf0)>>4); } }//4 first bits


            internal bool ToDistributionSystem { get { return (flagData&0x01)==0x01; } }//last bit
            internal bool FromDistributionSystem { get { return (flagData&0x02)==0x02; } }//second last bit
            internal bool MoreFragmentFlag { get { return (flagData&0x04)==0x04; } }
            internal bool Retry { get { return (flagData&0x08)==0x08; } }
            internal bool PowerManagement { get { return (flagData&0x10)==0x10; } }
            internal bool MoreData { get { return (flagData&0x20)==0x20; } }
            internal bool WEP { get { return (flagData&0x40)==0x40; } }
            internal bool Order { get { return (flagData&0x80)==0x80; } }//first bit

            internal FrameControl(byte firstByte, byte secondByte) {
                this.versionTypeSubtype=firstByte;
                this.flagData=secondByte;
            }
        }

        private FrameControl frameControl;
        private ushort duration;//The duration value is used for the Network Allocation Vector (NAV) calculation.
        PhysicalAddress sourceMAC, destinationMAC, transmitterMAC, recipientMAC, basicServiceSetMAC;
        private byte fragmentNibble;//4 bits
        private ushort sequenceNumber;//12 bits
        private int dataOffsetByteCount;

        public PhysicalAddress SourceMAC { get { return this.sourceMAC; } }
        public PhysicalAddress DestinationMAC { get { return this.destinationMAC; } }

        internal IEEE_802_11Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "IEEE 802.11") {

            this.frameControl=new FrameControl(parentFrame.Data[packetStartIndex], parentFrame.Data[packetStartIndex+1]);
            if (!this.ParentFrame.QuickParse) {
                this.Attributes.Add("Protocol version", this.frameControl.ProtocolVersion.ToString());
                this.Attributes.Add("Type", this.frameControl.Type.ToString());
                this.Attributes.Add("SubType", this.frameControl.SubType.ToString());
                this.Attributes.Add("WEP", this.frameControl.WEP.ToString());
            }

            this.duration = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2, true);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Duration",duration.ToString());

            int index=PacketStartIndex+4;
            byte[][] addresses=new byte[4][];
            /*
             * addresses[0]=The imediate (closest) recipient
             * addresses[1]=The station who is physically transmitting the message
             * addresses[2]=Original source address or final destination address
             * addresses[3]=Null or original source address
             * 
             * */

            for(int i=0;i<4;i++){
                addresses[i]=new byte[6];
                if(i<3){
                    if(index<packetEndIndex-4){
                        Array.Copy(parentFrame.Data, index, addresses[i], 0, addresses[i].Length);
                        index+=6;
                    }
                    else//there is no such address
                        addresses[i]=null;
                }
            }
            if(this.frameControl.Type==0 || this.frameControl.Type==2){//management or data frame
                //http://wifi.cs.st-andrews.ac.uk/animations/wifi%20frame.swf
                this.fragmentNibble=(byte)(parentFrame.Data[index]&0x0f);//I want the last 4 bits only
                this.sequenceNumber = (ushort)(Utils.ByteConverter.ToUInt16(parentFrame.Data, index, true) >> 4);//crop out the last 4 bits
                index+=2;

                //see if there is a 4th address
                if(frameControl.FromDistributionSystem && frameControl.ToDistributionSystem) {
                    Array.Copy(parentFrame.Data, index, addresses[3], 0, addresses[3].Length);
                    index+=6;
                }
            }
            //now check to see if there is an 802.11e QoS part of this packet that need to be skipped
            //http://standards.ieee.org/getieee802/download/802.11e-2005.pdf
            if(frameControl.Type==2 && frameControl.SubType>=8) {//data+QoS
                //The QoS Control field is a 16-bit field that identifies the TC or TS to which the frame belongs and various
                //other QoS-related information about the frame that varies by frame type and subtype.
                index+=2;// 16/8=2
            }

            this.dataOffsetByteCount=index-PacketStartIndex;

            if(this.frameControl.Type==0 || this.frameControl.Type==2){//management or data frame
                if(!frameControl.ToDistributionSystem && !frameControl.FromDistributionSystem) {//0,0
                    this.destinationMAC=new PhysicalAddress(addresses[0]);//DA
                    this.sourceMAC=new PhysicalAddress(addresses[1]);//SA
                    this.basicServiceSetMAC=new PhysicalAddress(addresses[2]);//BSSID
                    this.recipientMAC=null;//RA
                    this.transmitterMAC=null;//TA
                }
                else if(!frameControl.ToDistributionSystem && frameControl.FromDistributionSystem) {//0,1
                    this.destinationMAC=new PhysicalAddress(addresses[0]);
                    this.basicServiceSetMAC=new PhysicalAddress(addresses[1]);
                    this.sourceMAC=new PhysicalAddress(addresses[2]);
                    this.recipientMAC=null;
                    this.transmitterMAC=null;
                }
                else if(frameControl.ToDistributionSystem && !frameControl.FromDistributionSystem) {//0,1
                    this.basicServiceSetMAC=new PhysicalAddress(addresses[0]);
                    this.sourceMAC=new PhysicalAddress(addresses[1]);
                    this.destinationMAC=new PhysicalAddress(addresses[2]);
                    this.recipientMAC=null;
                    this.transmitterMAC=null;
                }
                else if(frameControl.ToDistributionSystem && !frameControl.FromDistributionSystem) {//1,1
                    this.recipientMAC=new PhysicalAddress(addresses[0]);//RA
                    this.transmitterMAC=new PhysicalAddress(addresses[1]);
                    this.destinationMAC=new PhysicalAddress(addresses[2]);
                    this.sourceMAC=new PhysicalAddress(addresses[3]);
                    this.basicServiceSetMAC=null;//message is sent between two different base stations!
                }
            }
            else if(this.frameControl.Type==1){//control frame
                if(addresses[0]!=null)
                    this.recipientMAC=new PhysicalAddress(addresses[0]);
                else
                    this.recipientMAC=null;
                if(addresses[1]!=null)
                    this.transmitterMAC=new PhysicalAddress(addresses[1]);
                else
                    this.transmitterMAC=null;
                this.destinationMAC=null;
                this.sourceMAC=null;
                this.basicServiceSetMAC=null;
            }

            if (!this.ParentFrame.QuickParse) {
                if (sourceMAC != null)
                    this.Attributes.Add("Source MAC", sourceMAC.ToString());
                if (destinationMAC != null)
                    this.Attributes.Add("Destination MAC", destinationMAC.ToString());
                if (transmitterMAC != null)
                    this.Attributes.Add("Transmitter MAC", transmitterMAC.ToString());
                if (recipientMAC != null)
                    this.Attributes.Add("Recipient MAC", recipientMAC.ToString());
                if (basicServiceSetMAC != null)
                    this.Attributes.Add("BSSID", basicServiceSetMAC.ToString());
            }
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;

            //int crcLength=4;
            int crcLength=0;
            //The CRC is often not in the sniffed frame/packet

            if(PacketStartIndex+dataOffsetByteCount<PacketEndIndex-crcLength) {
                //so how do I know what's inside this 802.11 packet?
                AbstractPacket packet;

                try {
                    //Logical-Link Control (LLC) maybe?
                    if(frameControl.Type==2) {//Data Frame
                        packet=new LogicalLinkControlPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex-crcLength);
                        //packet=new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex);
                    }

                    //Or IEEE 802.11 wireless LAN management frame?
                    else if(frameControl.Type==0) {
                        //todo: add parser for IEEE 802.11 wireless LAN management frame
                        packet=new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex-crcLength);
                    }

                    //Or something else?
                    else {
                        packet=new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex-crcLength);
                    }
                }
                catch(Exception e) {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+dataOffsetByteCount, PacketEndIndex-crcLength);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }

            //throw new Exception("The method or operation is not implemented.");
        }
    }
}
