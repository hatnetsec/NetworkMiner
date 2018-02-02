using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Events {
    public class NetworkHostEventArgs : EventArgs {

        public NetworkHost Host;

        public NetworkHostEventArgs(NetworkHost host) {
            this.Host=host;
        }
    }
}
