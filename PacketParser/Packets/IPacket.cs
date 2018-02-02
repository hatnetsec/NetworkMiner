using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public interface IPacket {
        Frame ParentFrame { get; }
        int PacketStartIndex { get; }
    }
}
