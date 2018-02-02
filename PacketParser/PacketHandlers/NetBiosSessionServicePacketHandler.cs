using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class NetBiosSessionServicePacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {
        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
        }

        public NetBiosSessionServicePacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) { }

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            int bytesParsed = 0;
            foreach (Packets.AbstractPacket p in packetList)
                //if(p.GetType().IsSubclassOf(typeof(Packets.NetBiosSessionService)))
                if (p.GetType() == typeof(Packets.NetBiosSessionService))
                    bytesParsed += ((Packets.NetBiosSessionService)p).ParsedBytesCount;
            return bytesParsed;
        }

        public void Reset() {
            //do nothing
        }
    }
}
