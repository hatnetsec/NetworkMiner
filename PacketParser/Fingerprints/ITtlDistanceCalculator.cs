using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Fingerprints {
    interface ITtlDistanceCalculator {
        bool TryGetTtlDistance(out byte ttlDistance, IEnumerable<Packets.AbstractPacket> packetList);
        byte GetTtlDistance(byte ipTimeToLive);
    }
}
