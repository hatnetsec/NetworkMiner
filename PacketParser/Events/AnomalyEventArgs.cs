using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Events {

    //ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/cpref2/html/T_System_EventArgs.htm
    public class AnomalyEventArgs : EventArgs {
        public string Message;
        public DateTime Timestamp;

        public AnomalyEventArgs(string anomalyMessage, DateTime anomalyTimestamp) {
            this.Message=anomalyMessage;
            this.Timestamp = anomalyTimestamp;
        }


    }

}
