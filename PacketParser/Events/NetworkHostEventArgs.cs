using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class HttpClientEventArgs : EventArgs {

        public NetworkHost Host;//TODO: ta bort denna
        public string HttpClientId;

        public HttpClientEventArgs(NetworkHost host, string httpClientId) {
            this.Host = host;
            this.HttpClientId = httpClientId;
        }

    }
}
