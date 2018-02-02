using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    /// <summary>
    /// Secure Socket Layer - works as an interface to host one or several TLS Records
    /// </summary>
    class SslPacket : AbstractPacket{

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            bool validTls=TlsRecordPacket.TryParse(parentFrame, packetStartIndex, packetEndIndex, out result);
            if(validTls){
                try {
                    result = new SslPacket(parentFrame, packetStartIndex, packetEndIndex);
                }
                catch {
                    result = null;
                }
            }
            return validTls && result!=null;
        }


        private SslPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Secure Socket Layer") {
            //is there no good way to check if this is a valid SSL packet?
            //try to parse the TLS record

        }




        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            int tlsRecordBytes=0;
            while(PacketStartIndex+tlsRecordBytes<PacketEndIndex) {
                AbstractPacket packet;
                try {
                    packet=new TlsRecordPacket(ParentFrame, PacketStartIndex+tlsRecordBytes, PacketEndIndex);
                }
                catch {
                    packet=new RawPacket(ParentFrame, PacketStartIndex+tlsRecordBytes, PacketEndIndex);
                }
                //tht TLS packets automatically shrinks if needed
                tlsRecordBytes+=packet.PacketByteCount;
                yield return packet;

                foreach(AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
            
        }
    }
}
