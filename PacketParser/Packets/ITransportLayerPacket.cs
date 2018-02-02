using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public interface ITransportLayerPacket : IPacket {
        byte DataOffsetByteCount { get; }
        ushort SourcePort { get; }
        ushort DestinationPort { get; }
        byte FlagsRaw { get; }
    }
}
