//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://dev.aol.com/aim/oscar/
    //http://fluentconsulting.com/components/Fluent.Toc/
    //http://en.wikipedia.org/wiki/OSCAR_protocol
    //http://oilcan.org/oscar/

    /**
     * This packet parser was written mainly as a result from the
     * philosecurity.org / SANS Network Forensics Puzzle Contest
     * http://philosecurity.org/2009/08/14/network-forensics-puzzle-contest
     * https://blogs.sans.org/computer-forensics/2009/08/19/network-forensics-puzzle-contest/
     */

    class OscarPacket : AbstractPacket, ISessionPacket {

        private string imText=null; //the im text sent
        private string destinationLoginId=null; //login ID of the receiver of the message
        private string sourceLoginId=null;
        private DateTime sourceUserSince=DateTime.MinValue;
        private int bytesToParse;

        internal string ImText { get { return this.imText; } }
        internal string DestinationLoginId { get { return this.destinationLoginId; } }
        internal string SourceLoginId { get { return this.sourceLoginId; } }
        internal int BytesParsed { get { return this.bytesToParse; } }

        enum FrameTypes : byte { SignOn=1, Data=2, Error=3, SignOff=4, KeepAlive=5 }
        enum SignonTags : ushort { ClientName=3, LoginCookie=6, MajorVersion=23, MinorVersion=24, PointVersion=25, BuildNum=26, MulticonnFlags=74, ClientReconnect=148 }


        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result = null;
            try {
                if(parentFrame.Data[packetStartIndex]!=0x2a)
                    return false;
                if (Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4) > packetEndIndex - packetStartIndex - 5)
                    return false;

                result = new OscarPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                return false;
            }
            return true;
        }

        internal OscarPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "OSCAR Instant Messaging Protocol") {
            //--FLAP HEADER START--//
            byte flapId = parentFrame.Data[PacketStartIndex];
            System.Diagnostics.Debug.Assert(flapId == 0x2a);//0x2a == '*'
            byte frameType = parentFrame.Data[PacketStartIndex+1];
            //skip number in sequence (2 bytes) (wraps at 0x7fff)
            ushort dataSize = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 4);
            this.bytesToParse=6+dataSize;
            if(base.PacketLength < dataSize)
                throw new Exception("Packet is not complete, wait for more TCP segments");
            int index = PacketStartIndex+6;
            //--FLAP HEADER END--//

            if(frameType == (byte)FrameTypes.SignOn) {
                //parse the signon message TLV's
                uint flapVersion = Utils.ByteConverter.ToUInt32(parentFrame.Data, index);
                System.Diagnostics.Debug.Assert(flapVersion == 1);
                index+=4;
                while(index < packetEndIndex && index < PacketStartIndex + this.bytesToParse) {
                    ushort tag = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                    index+=2;
                    ushort length = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                    index+=2;
                    //parse the tag data

                    if(Enum.IsDefined(typeof(SignonTags), tag)) {
                        string hexString = Utils.ByteConverter.ReadHexString(parentFrame.Data, (int)length, index);
                        string strString = Utils.ByteConverter.ReadString(parentFrame.Data, index, (int)length);
                        if (!this.ParentFrame.QuickParse)
                            base.Attributes.Add(((SignonTags)tag).ToString(), hexString+" ("+strString+")");
                    }
                    index+=length;
                }
            }
            else if(frameType == (byte)FrameTypes.Data) {
                //SNAC header (SNAC ID, flags, requestID)
                ushort foodGroup = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                index+=2;
                ushort type = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                index+=2;
                ushort flags = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                index+=2;
                uint requestId = Utils.ByteConverter.ToUInt32(parentFrame.Data, index);
                index+=4;

                //SNAC blob
                if(foodGroup == 4) {
                    if(type == 6) {
                        //SNAC: ICBM__CHANNEL_MSG_TOHOST - Foodgroup:4 Type:6
                        //skip 8 bytes ICBM cookie
                        index+=8;
                        ushort channel = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                        index+=2;
                        //Destination loginId, who should receive the message
                        this.destinationLoginId = Utils.ByteConverter.ReadLengthValueString(parentFrame.Data, ref index, 1);
                        if (!this.ParentFrame.QuickParse)
                            base.Attributes.Add("Destination User", this.destinationLoginId);
                        //icbmTlvs [Class: ICBM__TAGS] Message data and parameters; it must contain either the IM or DATA tag
                        while(index < parentFrame.Data.Length && index < packetEndIndex && index < PacketStartIndex + this.bytesToParse) {
                            TagLengthValue tlv = new TagLengthValue(parentFrame.Data, ref index);
                            if(tlv.Tag == (ushort)TagLengthValue.IcbmTag.IM_DATA) {
                                /**
                                 * [Class:ICBM__IM_DATA_TAGS] Message data for the IM channel only;
                                 * unlike other TLVs the order of TLVs inside this tag does matter
                                 * - it should be the CAPABILITIES item followed by multiple
                                 * IM_TEXT items
                                 */
                                int tlvIndex=0;
                                while(tlvIndex < tlv.Length) {
                                    TagLengthValue dataTlv = new TagLengthValue(tlv.Value, ref tlvIndex);
                                    if(dataTlv.Tag == (ushort)TagLengthValue.IcbmImDataTag.IM_TEXT) { //0x0101
                                        ushort encoding = Utils.ByteConverter.ToUInt16(dataTlv.Value, 0);
                                        ushort language = Utils.ByteConverter.ToUInt16(dataTlv.Value, 2);
                                        this.imText = Utils.ByteConverter.ReadString(dataTlv.Value, 4, dataTlv.Length - 4);
                                        if (!this.ParentFrame.QuickParse)
                                            base.Attributes.Add("IM Text", this.imText);
                                    }
                                }

                            }
                        }
                    }
                    else if(type == 7) {
                        //SNAC: ICBM__CHANNEL_MSG_TOCLIENT - Foodgroup:4 Type:7
                        /**
                         * This is the CHANNEL_MSG_TOHOST after it has been
                         * reformatted by the server and sent to the destination client.
                         **/
                        //skip 8 bytes cookie
                        index+=8;
                        ushort channel = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                        index+=2;
                        //OSERVICE__NickwInfo	Information about the sender of the message
                        this.sourceLoginId = Utils.ByteConverter.ReadLengthValueString(parentFrame.Data, ref index, 1);
                        ushort evil = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);//Warning level of user
                        index+=2;
                        //tlvBlock
                        uint nBlocks = Utils.ByteConverter.ToUInt16(parentFrame.Data, index);
                        index+=2;
                        for(int i=0; i<nBlocks; i++) {
                            TagLengthValue tlv =new TagLengthValue(parentFrame.Data, ref index);//[Class: OSERVICE__NICK_INFO_TAGS] TLV Block of user attributes
                            //http://dev.aol.com/aim/oscar/#OSERVICE__NICK_INFO_TAGS
                        }
                        //icbmTlvs	TLV	[Class: ICBM__TAGS] Actual message
                        while(index < parentFrame.Data.Length && index < packetEndIndex && index < PacketStartIndex + this.bytesToParse) {
                            TagLengthValue tlv = new TagLengthValue(parentFrame.Data, ref index);
                            if(tlv.Tag == (ushort)TagLengthValue.IcbmTag.IM_DATA) {
                                /**
                                 * [Class:ICBM__IM_DATA_TAGS] Message data for the IM channel only;
                                 * unlike other TLVs the order of TLVs inside this tag does matter
                                 * - it should be the CAPABILITIES item followed by multiple
                                 * IM_TEXT items
                                 */
                                int tlvIndex=0;
                                while(tlvIndex < tlv.Length) {
                                    TagLengthValue dataTlv = new TagLengthValue(tlv.Value, ref tlvIndex);
                                    if(dataTlv.Tag == (ushort)TagLengthValue.IcbmImDataTag.IM_TEXT) { //0x0101
                                        ushort encoding = Utils.ByteConverter.ToUInt16(dataTlv.Value, 0);
                                        ushort language = Utils.ByteConverter.ToUInt16(dataTlv.Value, 2);
                                        this.imText = Utils.ByteConverter.ReadString(dataTlv.Value, 4, dataTlv.Length - 4);
                                        if (!this.ParentFrame.QuickParse)
                                            base.Attributes.Add("IM Text", this.imText);
                                    }
                                }

                            }
                        }


                    }
                }
            }

        }

        private void ReadIcbmTags() {

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            get { return true; }
        }

        public int ParsedBytesCount {
            get { throw new Exception("The method or operation is not implemented."); }
        }

        #endregion

        internal class TagLengthValue {
            //http://dev.aol.com/aim/oscar/#TLV

            internal enum IcbmTag : ushort {
                IM_DATA = 2,
                REQUEST_HOST_ACK = 3,
                AUTO_RESPONSE = 4,
                DATA = 5,
                STORE = 6,
                WANT_EVENTS = 11,
                BART = 13,
                HOST_IM_ID = 16,
                HOST_IM_ARGS = 17,
                SEND_TIME = 22,
                FRIENDLY_NAME = 23,
                ANONYMOUS = 24,
                WIDGET_NAME = 25
            }

            internal enum IcbmImDataTag : ushort {
                IM_CAPABILITIES=0x0501, //TLV Class: ICBM__IM_DATA_TAGS
                IM_TEXT=0x0101,
                MIME_ARRAY=0x0D01
            }

            internal enum OserviceNickInfoTag : ushort {
                NICK_FLAGS=1,
                SIGNON_TOD=3,
                IDLE_TIME=4,
                MEMBER_SINCE=5,
                REALIPADDRESS=10,
                CAPS=13,
                ONLINE_TIME=15,
                MY_INSTANCE_NUM=20,
                SHORT_CAPS=25,
                BART_INFO=29,
                NICK_FLAGS2=31,
                BUDDYFEED_TIME=35,
                SIG_TIME=38,
                AWAY_TIME=39,
                GEO_COUNTRY=42
            }

            private ushort tag;
            private ushort length;
            private byte[] value;

            internal ushort Tag { get { return this.tag; } }
            internal ushort Length { get { return this.length; } }
            internal byte[] Value { get { return this.value; } }
            internal String ValueString { get { return Utils.ByteConverter.ReadString(this.value); } }

            internal TagLengthValue(byte[] data, ref int offset) {
                /**
                 * Name	    Type	Notes
                 * tag	    u16	    Numeric tag of the data, possible values are defined in the TLV class
                 *                  for the group of TLVs
                 * len	    u16     Length in bytes of the variable data
                 * value	blob	The data inside the TLV of len length; usually another datatype is used
                 *                  to represent the data - this is described in the TLV class
                 */
                this.tag = Utils.ByteConverter.ToUInt16(data, offset);
                offset+=2;
                this.length = Utils.ByteConverter.ToUInt16(data, offset);
                offset+=2;
                this.value = new byte[this.length];
                Array.Copy(data, offset, this.value, 0, this.length);
                offset+=this.length;
            }
        }
    }
}
