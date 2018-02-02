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
    /// Interface for packet handlers that are extracting info from packets inside a TCP session
    /// </summary>
    interface ITcpSessionPacketHandler {

        ApplicationLayerProtocol HandledProtocol { get;}

        /*
        /// <summary>
        /// Functions that implement this one should parse the data in the supplied protocol if it is of the right type
        /// </summary>
        /// <param name="tcpSession"></param>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="packetList"></param>
        /// <returns>Returns true if a packet of the specified protocol was complete and parsed successfully, otherwise false</returns>
        bool TryExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList);
        */


        int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<Packets.AbstractPacket> packetList);

        void Reset();//resets all captured data
        
    }
}
