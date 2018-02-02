using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class HpSwitchProtocolPacket : AbstractPacket{

        private byte version, type;

        internal HpSwitchProtocolPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "HP Switch Protocol") {

            this.version=parentFrame.Data[PacketStartIndex];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Version", "0x"+version.ToString("X2"));
            this.type=parentFrame.Data[PacketStartIndex+1];
            if (!this.ParentFrame.QuickParse)
                this.Attributes.Add("Type", "0x"+type.ToString("X2"));
            //System.Collections.Generic.List<HpSwField> fields= new List<HpSwField>();

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            int fieldCount=0;
            int dataPosition=PacketStartIndex+2;
            while(dataPosition<this.PacketEndIndex && fieldCount<20) {
                HpSwField field=new HpSwField(this.ParentFrame, dataPosition, this.PacketEndIndex);
                dataPosition+=field.PacketLength;
                fieldCount++;
                yield return field;
            }
        }

        internal class HpSwField : AbstractPacket{

            private byte typeByte;
            private byte valueLength;
            private byte[] valueBytes;
            

            internal byte TypeByte { get { return this.typeByte; } }
            internal byte[] ValueBytes { get { return this.valueBytes; } }
            internal string ValueString {
                get {
                    int i=0;
                    return Utils.ByteConverter.ReadNullTerminatedString(this.valueBytes, ref i, false, false, valueLength);
                }
            }
            //private string valueString;

            internal enum FieldType : byte { DeviceName=0x01, Version=0x02, Config=0x03, IpAddress=0x05, MacAddress=0x0e}

            internal HpSwField(Frame parentFrame, int packetStartIndex, int packetEndIndex)
                : base(parentFrame, packetStartIndex, packetEndIndex, "HP Switch Protocol Field") {
                this.typeByte=parentFrame.Data[PacketStartIndex];
                this.valueLength=parentFrame.Data[PacketStartIndex+1];
                //this.PacketEndIndex=PacketStartIndex+2+length;
                //int index=;
                this.valueBytes=new byte[Math.Min(valueLength, base.PacketLength-2)];
                Array.Copy(parentFrame.Data, PacketStartIndex+2, this.valueBytes, 0, this.valueBytes.Length);
                if (!this.ParentFrame.QuickParse)
                    this.Attributes.Add("Field 0x"+typeByte.ToString("X2"), ValueString);
                this.PacketEndIndex=PacketStartIndex+1+valueLength;
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if(includeSelfReference)
                    yield return this;
                yield break;//no sub packets
            }
        }
    }
}
