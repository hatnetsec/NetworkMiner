using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class SyslogPacket : AbstractPacket {

        private string syslogMessage = null;

        internal string SyslogMessage { get { return this.syslogMessage; } }

        internal SyslogPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Syslog") {
                if (packetEndIndex >= packetStartIndex) {
                    this.syslogMessage = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex, packetEndIndex - packetStartIndex + 1);
                    if (!this.ParentFrame.QuickParse)
                        base.Attributes.Add("Message", this.syslogMessage);
                }
        }
            


        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }
    }
}
