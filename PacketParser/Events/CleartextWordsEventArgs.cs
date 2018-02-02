using System;
using System.Collections.Generic;
using System.Text;
using System.Xml;
using System.Xml.Schema;

namespace PacketParser.Events {
    public class CleartextWordsEventArgs : EventArgs, System.Xml.Serialization.IXmlSerializable {
        //public IEnumerable<string> Words { get { return this.words; } }
        public IList<string> Words;
        public int WordCharCount;
        public int TotalByteCount;
        public long FrameNumber;
        public DateTime Timestamp;

        //private List<string> words;
        private CleartextWordsEventArgs() { }
        public CleartextWordsEventArgs(IList<string> words, int wordCharCount, int totalByteCount, long frameNumber, DateTime timestamp) {
            this.Words=words;
            this.WordCharCount=wordCharCount;
            this.TotalByteCount=totalByteCount;
            this.FrameNumber = frameNumber;
            this.Timestamp = timestamp;
        }

        public XmlSchema GetSchema() {
            return null;
        }

        public void ReadXml(XmlReader reader) {
            throw new NotImplementedException();
        }

        public void WriteXml(XmlWriter writer) {
            writer.WriteElementString("FrameNumber", this.FrameNumber.ToString());
            writer.WriteElementString("Timestamp", this.Timestamp.ToString());
            foreach(string word in this.Words) {
                writer.WriteStartElement("Word");
                writer.WriteString(word);
                writer.WriteEndElement();
            }
        }
    }
}
