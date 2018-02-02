using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class DnsRecordEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {

        public Packets.DnsPacket.IDnsResponseInfo Record;
        public NetworkHost DnsServer, DnsClient;
        public Packets.IPv4Packet IpPacket;
        public Packets.UdpPacket UdpPacket;
        //internal void ShowDnsRecord(Packets.DnsPacket.ResourceRecord record, NetworkHost dnsServer, NetworkHost dnsClient, Packets.IPv4Packet ipPakcet, Packets.UdpPacket udpPacket) {

        private DnsRecordEventArgs() { }

        public DnsRecordEventArgs(Packets.DnsPacket.IDnsResponseInfo record, NetworkHost dnsServer, NetworkHost dnsClient, Packets.IPv4Packet ipPakcet, Packets.UdpPacket udpPacket) {
            this.Record = record;
            this.DnsServer = dnsServer;
            this.DnsClient = dnsClient;
            this.IpPacket = ipPakcet;
            this.UdpPacket = udpPacket;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            string recordIP = "";
            string recordPrimaryName = "";
            if (this.Record.IP != null)
                recordIP = this.Record.IP.ToString();
            else if (this.Record.PrimaryName != null)
                recordPrimaryName = this.Record.PrimaryName;


            writer.WriteElementString("ClientIP", this.DnsClient.IPAddress.ToString());
            writer.WriteElementString("ClientPort", this.UdpPacket.DestinationPort.ToString());
            writer.WriteElementString("ServerIP", this.DnsServer.IPAddress.ToString());
            writer.WriteElementString("ServerPort", this.UdpPacket.SourcePort.ToString());
            writer.WriteElementString("FrameNumber", this.IpPacket.ParentFrame.FrameNumber.ToString());
            writer.WriteElementString("Timestamp", this.IpPacket.ParentFrame.Timestamp.ToString());
            writer.WriteElementString("DnsRecordTransactionID", this.Record.ParentPacket.TransactionId.ToString("X4"));
            writer.WriteElementString("DnsRecordName", this.Record.DNS);
            writer.WriteElementString("DnsRecordIP", recordIP);
            writer.WriteElementString("DnsRecordPrimaryName", recordPrimaryName);
            writer.WriteElementString("DnsRecordTTL", this.Record.TimeToLive.ToString());
            
        }
    }
}
