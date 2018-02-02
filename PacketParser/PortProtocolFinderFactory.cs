using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public class PortProtocolFinderFactory : ISessionProtocolFinderFactory {

        public PacketHandler PacketHandler { get; set; }

        public PortProtocolFinderFactory(PacketHandler packetHandler) {
            this.PacketHandler = packetHandler;
        }

        public ISessionProtocolFinder CreateProtocolFinder(NetworkFlow flow, long startFrameNumber) {
            if(flow.FiveTuple.Transport == FiveTuple.TransportProtocol.TCP)
                return new TcpPortProtocolFinder(flow, startFrameNumber, this.PacketHandler);
            else
                throw new Exception("There is only a protocol finder for TCP");
        }

    }
}
