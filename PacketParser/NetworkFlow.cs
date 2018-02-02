using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PacketParser {
    public class NetworkFlow {
        public FiveTuple FiveTuple { get; }
        public DateTime StartTime { get; }
        public DateTime EndTime { get; set; }
        public long BytesSentClient { get; set; }
        public long BytesSentServer { get; set; }
        
        //int PacketsSentServer { get; }//not required
        //int PacketsSentClient { get; }//not required

        public NetworkFlow(NetworkTcpSession networkTcpSession) : this(new FiveTuple(networkTcpSession.ClientHost, networkTcpSession.ClientTcpPort, networkTcpSession.ServerHost, networkTcpSession.ServerTcpPort, FiveTuple.TransportProtocol.TCP), networkTcpSession.StartTime, networkTcpSession.EndTime, networkTcpSession.ClientToServerTcpDataStream.TotalByteCount, networkTcpSession.ServerToClientTcpDataStream.TotalByteCount) {
            //nothing more required
        }

        public NetworkFlow(FiveTuple fiveTuple, DateTime startTime) : this(fiveTuple, startTime, startTime, 0, 0) {
            //nothing more required
        }

        public NetworkFlow(FiveTuple fiveTuple, DateTime startTime, DateTime endTime, long bytesSentClient, long bytesSentServer) {
            this.FiveTuple = fiveTuple;
            this.StartTime = startTime;
            this.EndTime = endTime;
            this.BytesSentClient = bytesSentClient;
            this.BytesSentServer = bytesSentServer;
        }

    }
}
