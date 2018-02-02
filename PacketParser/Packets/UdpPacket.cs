//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //User Datagram Protocol
    public class UdpPacket : AbstractPacket, ITransportLayerPacket {

        private ushort sourcePort;
        private ushort destinationPort;
        private ushort length;
        private ushort checksum;

        public ushort SourcePort { get { return sourcePort; } }
        public ushort DestinationPort { get { return destinationPort; } }
        public byte DataOffsetByteCount { get { return 8; } }
        public byte FlagsRaw { get { return 0; } }

        internal UdpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex) : base(parentFrame, packetStartIndex, packetEndIndex, "UDP") {

            this.sourcePort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Source Port", sourcePort.ToString());
            this.destinationPort = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Destination Port", destinationPort.ToString());

            this.length = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4);
            if(length!=packetEndIndex-packetStartIndex+1) {
                //can be due to IP fragmentation for example
                if (!this.ParentFrame.QuickParse)
                    parentFrame.Errors.Add(new Frame.Error(parentFrame, packetStartIndex+4, PacketStartIndex+5, "UDP defined length ("+length+") differs from actual length ("+(packetEndIndex-packetStartIndex+1)+")"));
                //use the smallest value..
                if(packetEndIndex>packetStartIndex+length-1) {
                    packetEndIndex=packetStartIndex+length-1;
                    base.PacketEndIndex=packetEndIndex;
                }
            }
            this.checksum = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 6);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            //List<Packet> subPackets=new List<Packet>();
            if(PacketStartIndex+8<PacketEndIndex) {
                AbstractPacket packet;
                /*
                if(destinationPort==53 || sourcePort==53 || destinationPort==5353 || sourcePort==5353) {//DNS or Multicast DNS http://www.multicastdns.org/
                    try {
                        packet=new DnsPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse DNS packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else if(destinationPort==67 || destinationPort==68 || sourcePort==67 || sourcePort==68) {
                    try {
                        packet=new DhcpPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse DHCP (or BOOTP) protocol: "+e.Message));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }

                }
                else if(destinationPort==69 || sourcePort==69) {
                    try {
                        packet=new TftpPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse NetBiosNameServicePacket packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else if(destinationPort==137 || sourcePort==137) {
                    try {
                        packet=new NetBiosNameServicePacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse NetBiosNameServicePacket packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else if(destinationPort==138 || sourcePort==138) {
                    try {
                        packet=new NetBiosDatagramServicePacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse NetBiosDatagramServicePacket packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else if (destinationPort == 514 || sourcePort == 514) {
                    try {
                        packet = new SyslogPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse Syslog packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if(destinationPort==1900 || sourcePort==1900) {
                    try {
                        packet=new UpnpPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse UPnP packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else if(destinationPort==5060 || sourcePort==5060) {
                    try {
                        packet=new SipPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                    catch(Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex+8, PacketEndIndex, "Cannot parse SIP packet ("+e.Message+")"));
                        packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                    }
                }
                else {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+8, PacketEndIndex);
                }
                 * */
                ApplicationLayerProtocol l7Protocol = UdpPortProtocolFinder.Instance.GetApplicationLayerProtocol(FiveTuple.TransportProtocol.UDP, sourcePort, destinationPort);

                if (l7Protocol == ApplicationLayerProtocol.Dns) {//DNS or Multicast DNS http://www.multicastdns.org/
                    try {
                        packet = new DnsPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse DNS packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.Dhcp) {
                    try {
                        packet = new DhcpPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse DHCP (or BOOTP) protocol: " + e.Message));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }

                }
                else if (l7Protocol == ApplicationLayerProtocol.Tftp) {
                    try {
                        packet = new TftpPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse NetBiosNameServicePacket packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.NetBiosNameService) {
                    try {
                        packet = new NetBiosNameServicePacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse NetBiosNameServicePacket packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.NetBiosDatagramService) {
                    try {
                        packet = new NetBiosDatagramServicePacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse NetBiosDatagramServicePacket packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.Syslog) {
                    try {
                        packet = new SyslogPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse Syslog packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.Upnp) {
                    try {
                        packet = new UpnpPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse UPnP packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.Sip) {
                    try {
                        packet = new SipPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse SIP packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else if (l7Protocol == ApplicationLayerProtocol.VXLAN) {
                    try {
                        packet = new VxlanPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                    catch (Exception e) {
                        if (!this.ParentFrame.QuickParse)
                            ParentFrame.Errors.Add(new Frame.Error(ParentFrame, PacketStartIndex + 8, PacketEndIndex, "Cannot parse VXLAN packet (" + e.Message + ")"));
                        packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                    }
                }
                else {
                    packet = new RawPacket(ParentFrame, PacketStartIndex + 8, PacketEndIndex);
                }
                yield return packet;
                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }


        
    }
}
