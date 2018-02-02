using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class CredentialEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {
        public NetworkCredential Credential;

        private CredentialEventArgs() { }
        public CredentialEventArgs(NetworkCredential credential) {
            this.Credential=credential;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("ClientIP", this.Credential.Client.IPAddress.ToString());
            writer.WriteElementString("ServerIP", this.Credential.Server.IPAddress.ToString());
            writer.WriteElementString("Protocol", this.Credential.ProtocolString);
            writer.WriteElementString("Username", this.Credential.Username);
            writer.WriteElementString("Password", this.Credential.Password);
            writer.WriteElementString("IsProvenValid", this.Credential.IsProvenValid.ToString());
            writer.WriteElementString("Timestamp", this.Credential.LoginTimestamp.ToString());
        }
    }
}
