//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

namespace PacketParser {
    public class NetworkHostList {
        private SortedDictionary<uint, NetworkHost> networkHostDictionary;

        public int Count { get { return networkHostDictionary.Count; } }
        public ICollection<NetworkHost> Hosts { get { return networkHostDictionary.Values; } }

        internal NetworkHostList() {
            this.networkHostDictionary=new SortedDictionary<uint, NetworkHost>();
        }

        internal void Clear() {
            this.networkHostDictionary.Clear();
        }

        internal bool ContainsIP(IPAddress ip) {
            uint ipUint = Utils.ByteConverter.ToUInt32(ip);
            return networkHostDictionary.ContainsKey(ipUint);
        }

        internal void Add(NetworkHost host) {
            //NetworkHost host=new NetworkHost(ip);
            //uint ipUint=ByteConverter.ToUInt32(host.IPAddress);
            this.networkHostDictionary.Add(Utils.ByteConverter.ToUInt32(host.IPAddress), host);
        }

        internal NetworkHost GetNetworkHost(IPAddress ip) {
            uint ipUint = Utils.ByteConverter.ToUInt32(ip);
            if(networkHostDictionary.ContainsKey(ipUint))
                return networkHostDictionary[ipUint];
            else
                return null;
        }

    }
}
