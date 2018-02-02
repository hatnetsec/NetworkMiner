using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    public class CotpPacket : AbstractPacket{
        private byte length;
        private byte pduType;
        private PayloadProtocol encapsulatedProtocol;

        internal enum PayloadProtocol { RDP, S7Comm }

        /*
        CR TPDU          Connection request TPDU        0xe
        CC TPDU          Connection confirm TPDU        0xd
        DR TPDU          Disconnect request TPDU        0x8
        DC TPDU          Disconnect confirm TPDU        0xa
        DT TPDU          Data TPDU                      0xf
        ED TPDU          Expedited data TPDU            0x1
        AK TPDU          Data acknowledge TPDU          0x6
        EA TPDU          Expedited acknowledge TPDU     0x2
        RJ TPDU          Reject TPDU                    0x5
        ER TPDU          Error TPDU                     0x7
        */
        internal enum Tpdu : byte {
            ConnectionRequest = 0xe,
            ConnectionConfirm = 0xd,
            DisconnectRequest = 0x8,
            DisconnectConfirm = 0xa,
            Data = 0xf,
            ExpeditedData = 0x1,
            DataAcknowledge = 0x6,
            ExpeditedAcknowledge = 0x2,
            Reject = 0x5,
            Error = 0x7,

            UNKNOWN = 0xff
        }
        
        internal Tpdu GetTpdu() {
            if (Enum.IsDefined(typeof(Tpdu), (byte)(this.pduType >> 4)))
                return (Tpdu)(this.pduType >> 4);
            else
                return Tpdu.UNKNOWN;
        }

        //https://www.ietf.org/rfc/rfc0905.txt
        internal CotpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, PayloadProtocol encapsulatedProtocol)
            : base(parentFrame, packetStartIndex, packetEndIndex, "ISO/IEC 8073/X.224 COTP") {

            this.encapsulatedProtocol = encapsulatedProtocol;
            this.length = parentFrame.Data[packetStartIndex];
            this.pduType = parentFrame.Data[packetStartIndex + 1];
            /**
             * 
             *    This field contains the TPDU code and is contained in octet 2  of
             *     the  header.  It is used to define the structure of the remaining
             *     header.  This field is a  full  octet  except  in  the  following
             *     cases:
             *            1110 xxxx     Connection Request      0xe
             *            1101 xxxx     Connection Confirm      0xd
             *            0101 xxxx     Reject                  0x5
             *            0110 xxxx     Data Acknowledgement    0x6
             */
    }

    public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            if(includeSelfReference)
                yield return this;

            AbstractPacket packet = null;
            if (this.encapsulatedProtocol == PayloadProtocol.RDP && this.GetTpdu() == Tpdu.ConnectionRequest)
                packet = new RdpPacket.Cookie(base.ParentFrame, base.PacketStartIndex + 7, base.PacketEndIndex);
            if(packet != null) {
                yield return packet;
                foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }
    }
}
