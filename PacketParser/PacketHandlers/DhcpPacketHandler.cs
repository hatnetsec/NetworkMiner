//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class DhcpPacketHandler : AbstractPacketHandler, IPacketHandler {

        private SortedList<string, System.Net.IPAddress> previousIpList;

        public DhcpPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            this.previousIpList=new SortedList<string, System.Net.IPAddress>();
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.DhcpPacket))
                    ExtractData(ref sourceHost, destinationHost, (Packets.DhcpPacket)p);
            }
        }

        public void Reset() {
            this.previousIpList.Clear();
        }

        #endregion

        private void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, Packets.DhcpPacket dhcpPacket) {
            if(dhcpPacket.OpCode==Packets.DhcpPacket.OpCodeValue.BootRequest && (sourceHost.MacAddress==null || dhcpPacket.ClientMacAddress!=sourceHost.MacAddress)) {
                sourceHost.MacAddress=dhcpPacket.ClientMacAddress;
            }
            else if(dhcpPacket.OpCode==Packets.DhcpPacket.OpCodeValue.BootReply && (destinationHost.MacAddress==null || dhcpPacket.ClientMacAddress!=destinationHost.MacAddress)) {
                destinationHost.MacAddress=dhcpPacket.ClientMacAddress;
            }

            if(dhcpPacket.OpCode==Packets.DhcpPacket.OpCodeValue.BootReply && (dhcpPacket.GatewayIpAddress!=null && dhcpPacket.GatewayIpAddress!=System.Net.IPAddress.None && dhcpPacket.GatewayIpAddress.Address>0))
                destinationHost.ExtraDetailsList["Default Gateway"]=dhcpPacket.GatewayIpAddress.ToString();


            System.Collections.Specialized.NameValueCollection optionParameterList = new System.Collections.Specialized.NameValueCollection();
            //now check all the DHCP options
            //byte dhcpMessageType=0x00;//1=Discover, 2=Offer, 3=Request, 5=Ack, 8=Inform
            foreach(Packets.DhcpPacket.Option option in dhcpPacket.OptionList) {
                //TODO: Add option to Parameters list

                

                if(option.OptionCode==12) {//hostname
                    string hostname = Utils.ByteConverter.ReadString(option.OptionValue);
                    sourceHost.AddHostName(hostname);
                    optionParameterList.Add("DHCP Option 12 Hostname", hostname);
                }
                else if(option.OptionCode==15) {//Domain Name
                    string domain = Utils.ByteConverter.ReadString(option.OptionValue);
                    sourceHost.AddDomainName(domain);
                    optionParameterList.Add("DHCP Option 15 Domain", domain);
                }
                else if(option.OptionCode==50) {//requested IP address
                    if(dhcpPacket.DhcpMessageType==3) {//Must be a DHCP Request
                        System.Net.IPAddress requestedIpAddress=new System.Net.IPAddress(option.OptionValue);
                        if(sourceHost.IPAddress!=requestedIpAddress) {
                            if(!base.MainPacketHandler.NetworkHostList.ContainsIP(requestedIpAddress)) {
                                NetworkHost clonedHost=new NetworkHost(requestedIpAddress);
                                clonedHost.MacAddress=sourceHost.MacAddress;
                                //foreach(string hostname in sourceHost.HostNameList)
                                //    clonedHost.AddHostName(hostname);
                                lock(base.MainPacketHandler.NetworkHostList)
                                    base.MainPacketHandler.NetworkHostList.Add(clonedHost);
                                //now change the host to the cloned one (and hope it works out...)
                                sourceHost=clonedHost;
                            }
                            else {
                                sourceHost=base.MainPacketHandler.NetworkHostList.GetNetworkHost(requestedIpAddress);
                                if(dhcpPacket.OpCode==Packets.DhcpPacket.OpCodeValue.BootRequest && (sourceHost.MacAddress==null || dhcpPacket.ClientMacAddress!=sourceHost.MacAddress)) {
                                    sourceHost.MacAddress=dhcpPacket.ClientMacAddress;
                                }
                            }
                        }
                        if(sourceHost.MacAddress!=null && previousIpList.ContainsKey(sourceHost.MacAddress.ToString())) {
                            //if(previousIpList.ContainsKey(sourceHost.MacAddress.ToString())) {
                            sourceHost.AddNumberedExtraDetail("Previous IP", previousIpList[sourceHost.MacAddress.ToString()].ToString());
                            //sourceHost.ExtraDetailsList["Previous IP"]=previousIpList[sourceHost.MacAddress.ToString()].ToString();
                            previousIpList.Remove(sourceHost.MacAddress.ToString());
                        }
                    }
                    else if(dhcpPacket.DhcpMessageType==1) {//DHCP discover
                        //see which IP address the client hade previously
                        //They normally requests the same IP as they hade before...
                        System.Net.IPAddress requestedIpAddress=new System.Net.IPAddress(option.OptionValue);
                        this.previousIpList[sourceHost.MacAddress.ToString()]=requestedIpAddress;
                    }
                }
                    /*
                else if(option.OptionCode==53) {//DHCP message type
                    if(option.OptionValue!=null && option.OptionValue.Length==1)
                        dhcpMessageType=option.OptionValue[0];
                }/*/
                else if(option.OptionCode==60) {//vendor class identifier
                    string vendorCode = Utils.ByteConverter.ReadString(option.OptionValue);
                    sourceHost.AddDhcpVendorCode(vendorCode);
                    optionParameterList.Add("DHCP Option 60 Vendor Code", vendorCode);
                }
                else if (option.OptionCode == 81) {//Client Fully Qualified Domain Name
                    string domain = Utils.ByteConverter.ReadString(option.OptionValue, 3, option.OptionValue.Length - 3);
                    sourceHost.AddHostName(domain);
                    optionParameterList.Add("DHCP Option 81 Domain", domain);
                }
                else if (option.OptionCode == 125) {//V-I Vendor-specific Information http://tools.ietf.org/html/rfc3925
                    uint enterpriceNumber = Utils.ByteConverter.ToUInt32(option.OptionValue, 0);
                    optionParameterList.Add("DHCP Option 125 Enterprise Number", enterpriceNumber.ToString());
                    byte dataLen = option.OptionValue[4];
                    if (dataLen > 0 && option.OptionValue.Length >= 5 + dataLen) {
                        string optionData = Utils.ByteConverter.ReadString(option.OptionValue, 5, dataLen);
                        optionParameterList.Add("DHCP Option 125 Data", optionData);    
                    }
                }
                else {
                    string optionValueString = Utils.ByteConverter.ReadString(option.OptionValue);
                    if (!System.Text.RegularExpressions.Regex.IsMatch(optionValueString, @"[^\u0020-\u007E]")) {
                        optionParameterList.Add("DHCP Option " + option.OptionCode.ToString(), optionValueString);
                    }
                }
            }
            if(optionParameterList.Count > 0) {
                //try to get the udp packet
                string sourcePort = "UNKNOWN";
                string destinationPort = "UNKNOWN";
                foreach (Packets.AbstractPacket p in dhcpPacket.ParentFrame.PacketList) {
                    if (p.GetType() == typeof(Packets.UdpPacket)) {
                        Packets.UdpPacket udpPacket = (Packets.UdpPacket)p;
                        sourcePort = "UDP "+udpPacket.SourcePort;
                        destinationPort = "UDP " + udpPacket.DestinationPort;
                        break;
                    }
                }
                Events.ParametersEventArgs ea = new Events.ParametersEventArgs(dhcpPacket.ParentFrame.FrameNumber, sourceHost, destinationHost, sourcePort, destinationPort, optionParameterList, dhcpPacket.ParentFrame.Timestamp, "DHCP Option");
                MainPacketHandler.OnParametersDetected(ea);
            }
        }
    }
}
