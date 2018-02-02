using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.PcapOverIP {
    class PcapOverIpReceiverFactory : NetworkMiner.ToolInterfaces.IPcapOverIpReceiverFactory {

        private ushort nextPortNumber = 57012;

        public void GetPcapOverIp(PacketParser.PacketHandler packetHandler, NetworkMiner.NetworkMinerForm.AddCaseFileCallback addCaseFileCallback, PcapFileHandler.PcapFileReader.CaseFileLoadedCallback caseFileLoadedCallback, System.ComponentModel.RunWorkerCompletedEventHandler completedEventHandler, System.Windows.Forms.IWin32Window owner) {
            ReceivePcapOverTcpForm receiveForm = new ReceivePcapOverTcpForm(packetHandler, addCaseFileCallback, caseFileLoadedCallback, completedEventHandler, this.nextPortNumber++);
            receiveForm.Show(owner);
        }

    }
}
