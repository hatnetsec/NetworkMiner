//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;
using System.Net;

namespace PacketParser {
    public class NetworkPacketList /*: System.Collections.Generic.List<NetworkPacket>*/{
        private long totalBytes;
        private long payloadBytes;
        private long cleartextBytes;
        private int packetCount;
        
        public int Count { get { return this.packetCount; } }
        public long TotalBytes { get { return this.totalBytes; } }
        public long PayloadBytes { get { return this.payloadBytes; } }
        public long CleartextBytes { get { return this.cleartextBytes; } }
        public double CleartextProcentage {
            get {
                if(cleartextBytes>0)
                    return (1.0*cleartextBytes)/payloadBytes;
                else
                    return 0.0;
            }
        }
        



        public NetworkPacketList() /*: base()*/{

        }

        public override string ToString() {
            return this.packetCount + " packets ("+this.TotalBytes.ToString("n0")+" Bytes), "+this.CleartextProcentage.ToString("p")+" cleartext ("+this.CleartextBytes.ToString("n0")+" of "+this.PayloadBytes.ToString("n0")+" Bytes)";
        }

        public void AddRange(IEnumerable<NetworkPacket> collection) {
            lock (this) {
                foreach (NetworkPacket p in collection)
                    Add(p);
            }
        }
        public void Add(NetworkPacket packet){
            lock (this) {
                //base.Add(packet);
                this.packetCount++;
                this.totalBytes += packet.PacketBytes;
                this.payloadBytes += packet.PayloadBytes;
                this.cleartextBytes += packet.CleartextBytes;
            }
        }

        /*
        public NetworkPacketList GetSubset(System.Net.IPAddress sourceIp, System.Net.IPAddress destinationIp) {
            NetworkPacketList list=new NetworkPacketList();
            lock (this) {
                foreach (NetworkPacket p in this) {
                    if (p.SourceHost.IPAddress.Equals(sourceIp) && p.DestinationHost.IPAddress.Equals(destinationIp))
                        list.Add(p);
                }
            }
            return list;
        }
        public NetworkPacketList GetSubset(System.Net.IPAddress sourceIp, ushort? sourceTcpPort, System.Net.IPAddress destinationIp, ushort? destinationTcpPort) {
            NetworkPacketList list=new NetworkPacketList();
            lock (this) {
                foreach (NetworkPacket p in this) {
                    if (p.SourceHost.IPAddress.Equals(sourceIp) && p.DestinationHost.IPAddress.Equals(destinationIp))
                        if (p.SourceTcpPort == sourceTcpPort && p.DestinationTcpPort == destinationTcpPort)
                            list.Add(p);
                }
            }
            return list;
        }


        public ICollection<KeyValuePair<ushort[], NetworkPacketList>> GetSubsetPerTcpPortPair() {

            //Dictionary<ushort, int> dictionary=new Dictionary<ushort, int>();
            Dictionary<uint, NetworkPacketList> dictionary=new Dictionary<uint,NetworkPacketList>();

            lock (this) {
                foreach (NetworkPacket p in this) {
                    if (p.SourceTcpPort != null && p.DestinationTcpPort != null) {
                        uint portKey = Utils.ByteConverter.ToUInt32((ushort)p.SourceTcpPort, (ushort)p.DestinationTcpPort);
                        if (dictionary.ContainsKey(portKey))
                            dictionary[portKey].Add(p);
                        else {
                            dictionary.Add(portKey, new NetworkPacketList());
                            dictionary[portKey].Add(p);
                        }
                    }
                }
            }

            //we must now convert the list to something more appropriate to return.
            List<KeyValuePair<ushort[], NetworkPacketList>> returnList=new List<KeyValuePair<ushort[],NetworkPacketList>>();
            foreach(uint portKey in dictionary.Keys){
                ushort[] ports=new ushort[2];
                ports[0]=(ushort)(portKey>>16);//source port
                ports[1]=(ushort)(portKey&0xffff);//destination port (mask last 16 bits)
                returnList.Add(new KeyValuePair<ushort[],NetworkPacketList>(ports, dictionary[portKey]));
            }
            return (ICollection<KeyValuePair<ushort[], NetworkPacketList>>)returnList;
        }

        public ICollection<KeyValuePair<ushort[], NetworkPacketList>> GetSubsetPerUdpPortPair() {
            Dictionary<uint, NetworkPacketList> dictionary=new Dictionary<uint, NetworkPacketList>();
            lock (this) {
                foreach (NetworkPacket p in this) {
                    if (p.SourceUdpPort != null && p.DestinationUdpPort != null) {
                        uint portKey = Utils.ByteConverter.ToUInt32((ushort)p.SourceUdpPort, (ushort)p.DestinationUdpPort);
                        if (dictionary.ContainsKey(portKey))
                            dictionary[portKey].Add(p);
                        else {
                            dictionary.Add(portKey, new NetworkPacketList());
                            dictionary[portKey].Add(p);
                        }
                    }
                }
            }
            //we must now convert the list to something more appropriate to return.
            List<KeyValuePair<ushort[], NetworkPacketList>> returnList=new List<KeyValuePair<ushort[], NetworkPacketList>>();
            foreach(uint portKey in dictionary.Keys) {
                ushort[] ports=new ushort[2];
                ports[0]=(ushort)(portKey>>16);//source port
                ports[1]=(ushort)(portKey&0xffff);//destination port (mask last 16 bits)
                returnList.Add(new KeyValuePair<ushort[], NetworkPacketList>(ports, dictionary[portKey]));
            }
            return (ICollection<KeyValuePair<ushort[], NetworkPacketList>>)returnList;
        }
        */

    }
}
