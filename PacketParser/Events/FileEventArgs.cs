using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class FileEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {

        public FileTransfer.ReconstructedFile File;

        private FileEventArgs() { }

        public FileEventArgs(FileTransfer.ReconstructedFile file) {
            this.File=file;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("SourceHost", this.File.SourceHost.IPAddress.ToString());
            writer.WriteElementString("SourcePort", this.File.SourcePortString);
            writer.WriteElementString("DestinationHost", this.File.DestinationHost.IPAddress.ToString());
            writer.WriteElementString("DestinationPort", this.File.DestinationPortString);
            writer.WriteElementString("Filename", this.File.Filename);
            writer.WriteElementString("FilePath", this.File.FilePath);
            writer.WriteElementString("FileSize", this.File.FileSizeString);
            writer.WriteElementString("FileStreamType", this.File.FileStreamType.ToString());
            writer.WriteElementString("MD5Sum", this.File.MD5Sum);
            //PacketParser.Utils.ByteConverter.ToXxdHexString(this.File.GetHeaderBytes(4))
            writer.WriteElementString("Details", this.File.Details);
            writer.WriteElementString("FrameNumber", this.File.InitialFrameNumber.ToString());
            writer.WriteElementString("Timestamp", this.File.Timestamp.ToString());
        }
    }
}
