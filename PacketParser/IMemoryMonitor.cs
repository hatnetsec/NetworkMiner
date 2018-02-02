using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface IMemoryMonitor {
        double PhysicalUsagePercent { get; }
    }
}
