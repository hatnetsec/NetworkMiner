using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public interface IPcapParser {

        /// <summary>
        /// This will get the CURRENT data link type
        /// </summary>
        //PcapFrame.DataLinkTypeEnum CurrentDataLinkType {get;}

        IList<PcapFrame.DataLinkTypeEnum> DataLinkTypes { get; }

        PcapFrame ReadPcapPacketBlocking();

        List<KeyValuePair<string, string>> Metadata { get; }

        
    }
}
