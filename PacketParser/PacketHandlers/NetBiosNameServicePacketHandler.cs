//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class NetBiosNameServicePacketHandler : AbstractPacketHandler, IPacketHandler {

        public NetBiosNameServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //do nothing more
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.NetBiosNameServicePacket))
                    ExtractData((Packets.NetBiosNameServicePacket)p, sourceHost);
            }
        }

        private void ExtractData(Packets.NetBiosNameServicePacket netBiosNameServicePacket, NetworkHost sourceHost) {
            if(netBiosNameServicePacket.QueriedNetBiosName!=null)
                sourceHost.AddQueriedNetBiosName(netBiosNameServicePacket.QueriedNetBiosName);
            if(netBiosNameServicePacket.AnsweredNetBiosName!=null) {
                if(base.MainPacketHandler.NetworkHostList.ContainsIP(netBiosNameServicePacket.AnsweredIpAddress))
                    base.MainPacketHandler.NetworkHostList.GetNetworkHost(netBiosNameServicePacket.AnsweredIpAddress).AddHostName(netBiosNameServicePacket.AnsweredNetBiosName);
            }
        }

        public void Reset() {
            //empty
        }

        #endregion
    }
}
