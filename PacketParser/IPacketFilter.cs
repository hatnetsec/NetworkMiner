using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface IPacketFilter {

        /// <summary>
        /// Checks if the filter is currently active, i.e. if it has rules to filter packets against
        /// </summary>
        bool IsActive { get; }

        /// <summary>
        /// Checks if a five tuple (src.ip, src.port, dst.ip, dst.port, TCP/UDP) matches a filter criteria.
        /// </summary>
        /// <param name="node1">IP address and port for host 1</param>
        /// <param name="node2">IP address and port for host 2</param>
        /// <param name="transportProtocolString">Transport protocol, can be "TCP", "UDP" or "SCTP"</param>
        /// <returns></returns>
        bool Matches(System.Net.IPEndPoint node1, System.Net.IPEndPoint node2, string transportProtocolString);

        
    }
}
