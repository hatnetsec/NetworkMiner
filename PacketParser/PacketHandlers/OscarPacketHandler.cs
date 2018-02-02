using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class OscarPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler{

        public OscarPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region ITcpSessionPacketHandler Members

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Oscar; }
        }

        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            Packets.OscarPacket oscarPacket=null;
            Packets.TcpPacket tcpPacket=null;
            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.OscarPacket)) {
                    oscarPacket = (Packets.OscarPacket)p;
                }
                else if(p.GetType()==typeof(Packets.TcpPacket)) {
                    tcpPacket = (Packets.TcpPacket)p;
                }
            }

            if(oscarPacket!=null && tcpPacket!=null) {
                if (oscarPacket.ImText != null) {
                    NetworkHost sourceHost, destinationHost;
                    if (transferIsClientToServer) {
                        sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                        destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                    }
                    else {
                        sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                        destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                    }
                    base.MainPacketHandler.OnMessageDetected(new PacketParser.Events.MessageEventArgs(ApplicationLayerProtocol.Oscar, sourceHost, destinationHost, oscarPacket.ParentFrame.FrameNumber, oscarPacket.ParentFrame.Timestamp, oscarPacket.SourceLoginId, oscarPacket.DestinationLoginId, oscarPacket.ImText, oscarPacket.ImText, Encoding.Default, oscarPacket.Attributes));
                }
                return oscarPacket.BytesParsed;
            }
            return 0;
        }

        public void Reset() {
            //do nothing
        }

        #endregion
    }
}
