//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/Ethernet#Ethernet_frame_types_and_the_EtherType_field
    //http://en.wikipedia.org/wiki/DIX
    class ArpPacket : AbstractPacket {

        ushort harwareType, operation;
        ushort protocolType;
        byte hardwareLength, protocolLength;
        //System.Net.NetworkInformation.PhysicalAddress senderHardwareAddress, senderProtocolAddress, targetHardwareAddress, targetProtocolAddress;
        byte[] senderHardwareAddress, senderProtocolAddress, targetHardwareAddress, targetProtocolAddress;

        //public byte[] SourceMACAddress { get { return this.sourceMAC;}}
        //public byte[] DestinationMACAddress {get {return this.destinationMAC;}}

        /// <summary>
        /// Sender MAC address
        /// </summary>
        internal System.Net.NetworkInformation.PhysicalAddress SenderHardwareAddress { get { return new System.Net.NetworkInformation.PhysicalAddress(senderHardwareAddress); } }
        //internal byte[] SenderHardwareAddress{get{return senderHardwareAddress;}}
        /// <summary>
        /// Receiver MAC address
        /// </summary>
        internal System.Net.NetworkInformation.PhysicalAddress TargetHardwareAddress { get { return new System.Net.NetworkInformation.PhysicalAddress(targetHardwareAddress); } }
        //internal byte[] TargetHardwareAddress{get{return targetHardwareAddress;}}

        internal System.Net.IPAddress SenderIPAddress{
            get{
                try{
                    return new System.Net.IPAddress(senderProtocolAddress);
                }
                catch{
                    return null;
                }
            }
        }
        internal System.Net.IPAddress TargetIPAddress{
            get{
                try{
                    return new System.Net.IPAddress(targetProtocolAddress);
                }
                catch{
                    return null;
                }
            }
        }


        internal ArpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "ARP") {

                this.harwareType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
                //(ushort)(256*parentFrame.Data[packetStartIndex]+parentFrame.Data[packetStartIndex+1]);
            if(this.harwareType!=1)
                if(!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex, packetStartIndex+1, "ARP HardwareType not Ethernet"));

            this.protocolType = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                //(ushort)(256*parentFrame.Data[packetStartIndex+2]+parentFrame.Data[packetStartIndex+3]);
            if(this.protocolType!=(ushort)Ethernet2Packet.EtherTypes.IPv4)
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex+2, packetStartIndex+3, "ARP ProtocolType not IPv4"));

            this.hardwareLength=parentFrame.Data[packetStartIndex+4];
            if(this.hardwareLength!=6)
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex+4, packetStartIndex+4, "ARP HardwareLength<>6 (not Ethernet)"));

            this.senderHardwareAddress=new byte[this.hardwareLength];
            this.targetHardwareAddress=new byte[this.hardwareLength];

            this.protocolLength=parentFrame.Data[packetStartIndex+5];
            if(this.protocolLength!=4)
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex+5, packetStartIndex+5, "ARP ProtocolLength<>4 (not IPv4) (it is: "+this.protocolLength+")"));
            this.senderProtocolAddress=new byte[this.protocolLength];
            this.targetProtocolAddress=new byte[this.protocolLength];

            this.operation = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
            //this.operation=(ushort)(256*parentFrame.Data[packetStartIndex+6]+parentFrame.Data[packetStartIndex+7]);
            if(this.operation!=1 && operation!=2)
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex+6, packetStartIndex+7, "ARP Operation not Request nor Reply"));

            if (!TryCopy(parentFrame.Data, packetStartIndex + 8, senderHardwareAddress, 0, this.hardwareLength)) {
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 8, packetStartIndex + 8 + this.hardwareLength, "Error retrieving sender hardware address from ARP packet"));
            }
            else if (!TryCopy(parentFrame.Data, packetStartIndex + 8 + this.hardwareLength, senderProtocolAddress, 0, this.protocolLength)) {
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 8 + this.hardwareLength, packetStartIndex + 8 + this.hardwareLength + this.protocolLength, "Error retrieving sender protocol address from ARP packet"));
            }
            else if (!TryCopy(parentFrame.Data, packetStartIndex + 8 + this.hardwareLength + this.protocolLength, targetHardwareAddress, 0, this.hardwareLength)) {
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 8 + this.hardwareLength + this.protocolLength, packetStartIndex + 8 + 2 * this.hardwareLength + this.protocolLength, "Error retrieving target hardware address from ARP packet"));
            }
            else if (!TryCopy(parentFrame.Data, packetStartIndex + 8 + 2 * this.hardwareLength + this.protocolLength, targetProtocolAddress, 0, this.protocolLength)) {
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex + 8 + 2 * this.hardwareLength + this.protocolLength, packetStartIndex + 8 + 2 * this.hardwareLength + 2 * this.protocolLength, "Error retrieving target protocol address from ARP packet"));
            }
        }

        private bool TryCopy(Array sourceArray, int sourceIndex, Array destinationArray, int destinationIndex, int length) {
            if(sourceIndex<0 || sourceIndex>=sourceArray.Length || sourceIndex+length>sourceArray.Length)
                return false;
            if(destinationIndex<0 || destinationIndex+length>destinationArray.Length)
                return false;
            try {
                Array.Copy(sourceArray, sourceIndex, destinationArray, destinationIndex, length);
            }
            catch {
                return false;
            }
            return true;
        }

     
        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //return nothing
            yield break;
        }


        /*
        public override string ToString() {
            StringBuilder sbDataReceived=new StringBuilder();
            char c;
            for(int byteCounter=54; byteCounter+EthernetFrameOffset<data.Length && byteCounter<256; byteCounter++) {
                c=(char)data[EthernetFrameOffset+byteCounter];
                if(Char.IsLetterOrDigit(c) || Char.IsSymbol(c) || Char.IsWhiteSpace(c))
                    sbDataReceived.Append(c);
                else
                    sbDataReceived.Append(".");
            }
            return sbDataReceived.ToString();
        }
         * */

    }
}
