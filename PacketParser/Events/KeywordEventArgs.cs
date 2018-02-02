using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class KeywordEventArgs : System.Xml.Serialization.IXmlSerializable {

        public Frame Frame;
        public int KeywordIndex, KeywordLength;
        public NetworkHost SourceHost, DestinationHost;
        public string SourcePort, DestinationPort;

        private KeywordEventArgs() { }
        public KeywordEventArgs(Frame frame, int keywordIndex, int keywordLength, NetworkHost sourceHost, NetworkHost destinationHost, string sourcePort, string destinationPort) {
            this.Frame=frame;
            this.KeywordIndex=keywordIndex;
            this.KeywordLength=keywordLength;
            this.SourceHost=sourceHost;
            this.DestinationHost=destinationHost;
            this.SourcePort=sourcePort;
            this.DestinationPort=destinationPort;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            string keywordString = "";
            string keywordHexString = "";
            for (int i = 0; i < this.KeywordLength; i++) {
                keywordString += (char)this.Frame.Data[this.KeywordIndex + i];
                keywordHexString += this.Frame.Data[this.KeywordIndex + i].ToString("X2");
            }

            writer.WriteElementString("Keyword", System.Text.RegularExpressions.Regex.Replace(keywordString, @"[^ -~]", ".") + " [0x" + keywordHexString + "]");
            writer.WriteElementString("SourceIP", this.SourceHost.IPAddress.ToString());
            writer.WriteElementString("SourcePort", this.SourcePort.ToString());
            writer.WriteElementString("DestinationIP", this.DestinationHost.IPAddress.ToString());
            writer.WriteElementString("DestinationPort", this.DestinationPort.ToString());
            writer.WriteElementString("FrameNr", this.Frame.FrameNumber.ToString());
            writer.WriteElementString("Timestamp", this.Frame.Timestamp.ToString());
            writer.WriteElementString("Context", PacketParser.Utils.StringManglerUtil.GetReadableContextString(this.Frame.Data, this.KeywordIndex, this.KeywordLength));
           
        }
    }
}
