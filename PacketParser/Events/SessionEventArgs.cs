using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class SessionEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {
        //public NetworkTcpSession NetworkTcpSession;

        public PacketParser.ApplicationLayerProtocol Protocol;
        public NetworkHost Client;
        public NetworkHost Server;
        public ushort ClientPort;
        public ushort ServerPort;
        public bool Tcp;
        public long StartFrameNumber;
        public DateTime StartTimestamp;

        private NetworkFlow flow;

        public NetworkFlow Flow { get { return this.flow; } }

        private SessionEventArgs() { }
        public SessionEventArgs(NetworkFlow flow, PacketParser.ApplicationLayerProtocol protocol, long startFrameNumber) {
            this.Protocol = protocol;
            this.Client = flow.FiveTuple.ClientHost;
            this.Server = flow.FiveTuple.ServerHost;
            this.ClientPort = flow.FiveTuple.ClientPort;
            this.ServerPort = flow.FiveTuple.ServerPort;
            this.Tcp = flow.FiveTuple.Transport == FiveTuple.TransportProtocol.TCP;
            this.StartFrameNumber = startFrameNumber;
            this.StartTimestamp = flow.StartTime;
            this.flow = flow;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("ClientIP", this.Client.IPAddress.ToString());
            writer.WriteElementString("ClientPort", this.ClientPort.ToString());
            writer.WriteElementString("ServerIP", this.Server.IPAddress.ToString());
            writer.WriteElementString("ServerPort", this.ServerPort.ToString());
            writer.WriteElementString("TCP", this.Tcp.ToString());
            writer.WriteElementString("Protocol", this.Protocol.ToString());
            writer.WriteElementString("StartFrameNr", this.StartFrameNumber.ToString());
            writer.WriteElementString("StartTimestamp", this.StartTimestamp.ToString());
        }
    }
}
