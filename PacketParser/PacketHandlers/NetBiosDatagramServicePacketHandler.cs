//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class NetBiosDatagramServicePacketHandler : AbstractPacketHandler, IPacketHandler {

        public NetBiosDatagramServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty..
        }

        #region IPacketHandler Members

        public void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.NetBiosDatagramServicePacket))
                    ExtractData((Packets.NetBiosDatagramServicePacket)p, sourceHost);
            }
        }

        private void ExtractData(Packets.NetBiosDatagramServicePacket netBiosDatagramServicePacket, NetworkHost sourceHost) {

            if(netBiosDatagramServicePacket!=null) {
                if(netBiosDatagramServicePacket.SourceNetBiosName!=null && netBiosDatagramServicePacket.SourceNetBiosName.Length>0)
                    sourceHost.AddHostName(netBiosDatagramServicePacket.SourceNetBiosName);
            }
        }

        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
