using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Fingerprints {
    public interface IOsFingerprinter {

        /// <summary>
        /// Tries to guess the OS based on packets provided in a packet list
        /// </summary>
        /// <param name="osList">List to be populated with OS strings which matches the packetList</param>
        /// <param name="packetList">List of packets to used in order to perform the fingerpritning</param>
        /// <returns>Returns true if one or several OS's are detected</returns>
        //bool TryGetOperatingSystems(out IList<string> osList, IEnumerable<Packets.AbstractPacket> packetList);

        bool TryGetOperatingSystems(out IList<DeviceFingerprint> osList, IEnumerable<Packets.AbstractPacket> packetList);

        double Confidence { get; }

        //byte GetTtlDistance(Packets.IPv4Packet ipv4Packet, Packets.TcpPacket tcpPacket);
        //byte GetTtlDistance(byte ipv4PacketTimeToLive);
        string Name { get;}
    }
}
