using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface ISessionProtocolFinderFactory {
        PacketHandler PacketHandler { get; set; }
        ISessionProtocolFinder CreateProtocolFinder(NetworkFlow flow, long startFrameNumber);
    }
}
