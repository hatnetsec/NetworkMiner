using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class MessageEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {
        private const int MAX_SUBJECT_LENGTH = 50;

        public PacketParser.ApplicationLayerProtocol Protocol;
        public NetworkHost SourceHost;
        public NetworkHost DestinationHost;
        public long StartFrameNumber;
        public DateTime StartTimestamp;

        public string From;
        public string To;
        public string Subject;
        public string Message;
        public System.Text.Encoding MessageEncoding;
        public System.Collections.Specialized.NameValueCollection Attributes;

        private MessageEventArgs() { }//fore serialization purposes

        public MessageEventArgs(PacketParser.ApplicationLayerProtocol protocol, NetworkHost sourceHost, NetworkHost destinationHost, long startFrameNumber, DateTime startTimestamp, string from, string to, string subject, string message, System.Collections.Specialized.NameValueCollection attributes) : this(protocol, sourceHost, destinationHost, startFrameNumber, startTimestamp, from, to, subject, message, Encoding.Default, attributes) { }

        public MessageEventArgs(PacketParser.ApplicationLayerProtocol protocol, NetworkHost sourceHost, NetworkHost destinationHost, long startFrameNumber, DateTime startTimestamp, string from, string to, string subject, string message, Encoding messageEncoding, System.Collections.Specialized.NameValueCollection attributes) {
            this.Protocol = protocol;
            this.SourceHost = sourceHost;
            this.DestinationHost = destinationHost;
            this.StartFrameNumber = startFrameNumber;
            this.StartTimestamp = startTimestamp;
            this.From = from;
            this.To = to;
            this.Subject = subject;
            if (this.Subject != null && this.Subject.Length > MAX_SUBJECT_LENGTH)
                this.Subject = this.Subject.Substring(0, MAX_SUBJECT_LENGTH) + "...";
            this.Message = message;
            if (messageEncoding == null)
                this.MessageEncoding = Encoding.Default;
            else
                this.MessageEncoding = messageEncoding;
            this.Attributes = attributes;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            foreach (string name in this.Attributes.Keys) {
                writer.WriteAttributeString(name, this.Attributes[name]);
            }
            writer.WriteElementString("SourceHost", this.SourceHost.IPAddress.ToString());
            writer.WriteElementString("DestinationHost", this.DestinationHost.IPAddress.ToString());
            writer.WriteElementString("StartFrameNumber", this.StartFrameNumber.ToString());
            writer.WriteElementString("StartTimestamp", this.StartTimestamp.ToLongTimeString());
            writer.WriteElementString("From", this.From);
            writer.WriteElementString("To", this.To);
            writer.WriteElementString("Subject", this.Subject);
            writer.WriteElementString("Message", this.Message);
            writer.WriteElementString("Encoding", this.MessageEncoding.ToString());
        }
    }
}
