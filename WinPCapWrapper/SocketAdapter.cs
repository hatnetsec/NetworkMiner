//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;

namespace NetworkWrapper {
    public class SocketAdapter : IAdapter{
        private IPAddress ip;
        System.Net.NetworkInformation.NetworkInterface nic;
        private PacketReceivedEventArgs.PacketTypes basePacketType;

        public PacketReceivedEventArgs.PacketTypes BasePacketType { get { return basePacketType; } }
        public IPAddress IP{get{return ip;}}

        /*SocketAdapter(IPAddress ip) {
            this.ip=ip;
        }*/
        SocketAdapter(NetworkInterface nic, IPAddress ip) {
            this.nic=nic;
            this.ip=ip;
            if(nic.Supports(NetworkInterfaceComponent.IPv4) && ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetwork)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv4Packet;
            else if(nic.Supports(NetworkInterfaceComponent.IPv6) && ip.AddressFamily==System.Net.Sockets.AddressFamily.InterNetworkV6)
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv6Packet;
            else//use IPv4 as default
                this.basePacketType=PacketReceivedEventArgs.PacketTypes.IPv4Packet;

            /*
            UnicastIPAddressInformationCollection ipAddressCollection=nic.GetIPProperties().UnicastAddresses;
            if (ipAddressCollection.Count > 0)
                this.ip = ipAddressCollection[0].Address;
            else this.ip = IPAddress.None;
             * */

        }

        public override string ToString() {
            //return "Socket: "+ip.ToString();
            return "Socket: "+nic.Description+" ("+ip.ToString()+")";
        }

        public static List<IAdapter> GetAdapters() {
            //IPAddress[] ipAdresses=Dns.Resolve(Dns.GetHostName()).AddressList;
            //IPAddress[] ipAdresses=Dns.GetHostEntry(Dns.GetHostName()).AddressList;
            NetworkInterface[] nics=NetworkInterface.GetAllNetworkInterfaces();
            List<IAdapter> adapters=new List<IAdapter>(nics.Length);

            foreach(NetworkInterface nic in nics) {
                
                foreach(UnicastIPAddressInformation unicastIpInfo in nic.GetIPProperties().UnicastAddresses)
                    if(unicastIpInfo.Address!=null && !unicastIpInfo.Address.IsIPv6LinkLocal)
                        adapters.Add(new SocketAdapter(nic, unicastIpInfo.Address));
                //adapters.Add(new SocketAdapter(nic));
            }
            return adapters;
        }
    }
}
