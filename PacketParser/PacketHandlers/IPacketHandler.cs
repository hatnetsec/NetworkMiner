//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {

    /// <summary>
    /// Used to extract data from packets when source and destination hosts are known, but not packets inside a TCP session since that is handled by ITcpSessionPacketHandler
    /// </summary>
    interface IPacketHandler {
        //string HandledProtocol { get; }
        //void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IList<NetworkMiner.Packets.AbstractPacket> packetList);
        void ExtractData(ref NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList);
        void Reset();//resets all captured data
    }
}
