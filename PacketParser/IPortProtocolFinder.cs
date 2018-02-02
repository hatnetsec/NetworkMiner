using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface IPortProtocolFinder {
        PacketParser.ApplicationLayerProtocol GetApplicationLayerProtocol(PacketParser.FiveTuple.TransportProtocol transport, ushort sourcePort, ushort destinationPort);
    }
}
