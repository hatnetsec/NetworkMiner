using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public interface IPcapParserFactory {
        IPcapParser CreatePcapParser(IPcapStreamReader pcapStreamReader);
    }
}
