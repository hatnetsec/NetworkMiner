using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface IPcapOverIpReceiverFactory {

        void GetPcapOverIp(PacketParser.PacketHandler packetHandler, NetworkMinerForm.AddCaseFileCallback addCaseFileCallback, PcapFileHandler.PcapFileReader.CaseFileLoadedCallback caseFileLoadedCallback, System.ComponentModel.RunWorkerCompletedEventHandler completedEventHandler, System.Windows.Forms.IWin32Window owner);
    }
}
