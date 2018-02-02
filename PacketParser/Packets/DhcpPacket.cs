//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://en.wikipedia.org/wiki/DHCP
    //http://tools.ietf.org/html/rfc951
    class DhcpPacket : AbstractPacket {

        internal enum OpCodeValue : byte { BootRequest=0x01, BootReply=0x02 }

        private OpCodeValue opCode;
        private uint transactionID;
        private ushort secondsElapsed;
        private System.Net.IPAddress clientIpAddress, yourIpAddress, serverIpAddress, gatewayIpAddress;
        private System.Net.NetworkInformation.PhysicalAddress clientMacAddress;
        private List<Option> optionList;
        private byte dhcpMessageType;//1=Discover, 2=Offer, 3=Request, 5=Ack, 8=Inform

        internal OpCodeValue OpCode { get { return this.opCode; } }
        internal uint TransactionID { get { return this.transactionID; } }
        internal ushort SecondsElapsed { get { return this.secondsElapsed; } }
        internal System.Net.IPAddress ClientIpAddress { get { return this.clientIpAddress; } }
        internal System.Net.IPAddress YourIpAddress { get { return this.yourIpAddress; } }
        internal System.Net.IPAddress ServerIpAddress { get { return this.serverIpAddress; } }
        internal System.Net.IPAddress GatewayIpAddress { get { return this.gatewayIpAddress; } }
        internal System.Net.NetworkInformation.PhysicalAddress ClientMacAddress { get { return this.clientMacAddress; } }
        internal IList<Option> OptionList { get { return (IList<Option>)optionList; } }
        internal byte DhcpMessageType { get { return this.dhcpMessageType; } }


        internal DhcpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "DHCP (Bootstrap protocol)") {
            this.opCode=(OpCodeValue)parentFrame.Data[packetStartIndex];
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("OpCode", this.OpCode.ToString());
            //skip hardware type
            //skip hlen
            //skip hops
            this.transactionID = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 4);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Transaction ID", "0x"+this.transactionID.ToString("X2"));
            this.secondsElapsed = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 8);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Seconds elapsed", this.secondsElapsed.ToString());
            //skip flags (unused in BOOTP)

            byte[] ipAddrArray=new byte[4];
            Array.ConstrainedCopy(parentFrame.Data, packetStartIndex+12, ipAddrArray, 0, 4);
            clientIpAddress=new System.Net.IPAddress(ipAddrArray);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Client IP Address", this.clientIpAddress.ToString());
            Array.ConstrainedCopy(parentFrame.Data, packetStartIndex+16, ipAddrArray, 0, 4);//do I need to create a new byte[4] before this one?
            yourIpAddress=new System.Net.IPAddress(ipAddrArray);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Your IP Address", this.yourIpAddress.ToString());
            Array.ConstrainedCopy(parentFrame.Data, packetStartIndex+20, ipAddrArray, 0, 4);
            serverIpAddress=new System.Net.IPAddress(ipAddrArray);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Server IP Address", this.serverIpAddress.ToString());
            Array.ConstrainedCopy(parentFrame.Data, packetStartIndex+24, ipAddrArray, 0, 4);
            gatewayIpAddress=new System.Net.IPAddress(ipAddrArray);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Gateway IP Address", this.gatewayIpAddress.ToString());
            
            byte[] macAddrArray=new byte[6];
            Array.ConstrainedCopy(parentFrame.Data, packetStartIndex+28, macAddrArray, 0, 6);
            clientMacAddress=new System.Net.NetworkInformation.PhysicalAddress(macAddrArray);
            if (!this.ParentFrame.QuickParse)
                base.Attributes.Add("Client MAC Address", this.clientMacAddress.ToString());
            //skip extra 10 bytes of client hardware address

            //Skip 192 octets of 0's. BOOTP legacy
            //64  - optional server host name
            //128 - boot file name
            //skip magic cookie (4 bytes)
            optionList=new List<Option>();
            int index=packetStartIndex+240;//0x011A - 0x002A = 0xF0
            while(index<packetEndIndex) {
                Option option=new Option(parentFrame.Data, index);
                if(option.OptionCode==0xff)//check for "End Option"
                    break;
                if(option.OptionCode==3)//Default Gateway (router)
                    this.gatewayIpAddress=new System.Net.IPAddress(option.OptionValue);
                else if(option.OptionCode==53) {//extract the DHCP Message Type: 1=Discover, 2=Offer, 3=Request, 5=Ack, 8=Inform
                    if(option.OptionValue!=null && option.OptionValue.Length==1)
                        this.dhcpMessageType=option.OptionValue[0];
                }
                optionList.Add(option);
                if (!this.ParentFrame.QuickParse) {
                    base.Attributes.Add("DHCP Options", option.OptionCode.ToString());
                }
                index+=option.OptionValue.Length+2;
            }

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }

        //http://www.iana.org/assignments/bootp-dhcp-parameters
        internal class Option {
            //I could do an enum of all the DHCP Options listed in: RFC2132, but that's too much work
            //int optionStartIndex;

            byte optionCode;
            byte dataLength;
            byte[] value;

            //internal int NextOptionIndex { get { return this.optionStartIndex+this.dataLength+2; } }
            internal byte OptionCode { get { return optionCode; } }
            internal byte[] OptionValue { get { return value; } }

            internal Option(byte[] frameData, int optionStartIndex) {
                //this.optionStartIndex=optionStartIndex;
                this.optionCode=frameData[optionStartIndex];
                this.dataLength=frameData[optionStartIndex+1];
                this.value=new byte[dataLength];
                Array.ConstrainedCopy(frameData, optionStartIndex+2, this.value, 0, dataLength);
            }

        }
    }
}
