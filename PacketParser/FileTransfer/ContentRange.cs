using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    internal class ContentRange {
        internal long Start;
        internal long End;
        internal long Total;
    }
}
