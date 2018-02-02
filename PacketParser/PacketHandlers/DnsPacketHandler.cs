//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class DnsPacketHandler : AbstractPacketHandler, IPacketHandler {

        public DnsPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            Packets.DnsPacket dnsPacket=null;
            Packets.IPv4Packet ipv4Packet=null;
            Packets.IPv6Packet ipv6Packet=null;
            Packets.UdpPacket udpPacket=null;

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.DnsPacket))
                    dnsPacket=(Packets.DnsPacket)p;
                else if(p.GetType()==typeof(Packets.IPv4Packet))
                    ipv4Packet=(Packets.IPv4Packet)p;
                /*else if(p.GetType()==typeof(Packets.IPv6Packet))
                    ipv6Packet=(Packets.IPv6Packet)p;*/
                else if(p.GetType()==typeof(Packets.UdpPacket))
                    udpPacket=(Packets.UdpPacket)p;
            }

            if(dnsPacket!=null) {

                //ExtractDnsData(dnsPacket);
                if(dnsPacket.Flags.Response) {
                    System.Collections.Specialized.NameValueCollection cNamePointers=new System.Collections.Specialized.NameValueCollection();
                    if (dnsPacket.AnswerRecords != null && dnsPacket.AnswerRecords.Length > 0) {
                        foreach (Packets.DnsPacket.ResourceRecord r in dnsPacket.AnswerRecords) {
                            if (r.IP != null) {
                                if (!base.MainPacketHandler.NetworkHostList.ContainsIP(r.IP)) {
                                    NetworkHost host = new NetworkHost(r.IP);
                                    host.AddHostName(r.DNS);
                                    lock(base.MainPacketHandler.NetworkHostList)
                                        base.MainPacketHandler.NetworkHostList.Add(host);
                                    MainPacketHandler.OnNetworkHostDetected(new Events.NetworkHostEventArgs(host));
                                    //base.MainPacketHandler.ParentForm.ShowDetectedHost(host);
                                }
                                else
                                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(r.IP).AddHostName(r.DNS);
                                if (cNamePointers[r.DNS] != null)
                                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(r.IP).AddHostName(cNamePointers[r.DNS]);

                            }
                            else if (r.Type == (ushort)Packets.DnsPacket.RRTypes.CNAME) {
                                cNamePointers.Add(r.PrimaryName, r.DNS);
                            }

                            if (ipv4Packet != null) {
                                MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(r, sourceHost, destinationHost, ipv4Packet, udpPacket));
                                //base.MainPacketHandler.ParentForm.ShowDnsRecord(r, sourceHost, destinationHost, ipPakcet, udpPacket);
                            }
                        }
                    }
                    else {
                        //display the flags instead
                        //TODO : MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(
                        if(ipv4Packet !=null && dnsPacket.QueriedDnsName != null && dnsPacket.QueriedDnsName.Length > 0)
                            MainPacketHandler.OnDnsRecordDetected(new Events.DnsRecordEventArgs(new Packets.DnsPacket.ResponseWithErrorCode(dnsPacket), sourceHost, destinationHost, ipv4Packet, udpPacket));

                        
                    }
                }
                else {//DNS request
                    if(dnsPacket.QueriedDnsName!=null && dnsPacket.QueriedDnsName.Length>0)
                        sourceHost.AddQueriedDnsName(dnsPacket.QueriedDnsName);
                }

            }
        }

        public void Reset() {
            //do nothing since this class holds no state
        }

        #endregion
    }
}
