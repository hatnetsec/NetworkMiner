using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    /// <summary>
    /// This class is only used for decapsulating the packets inside an OpenFlow stream.
    /// Metadata attributes from the OpenFlow session itself is not extracted.
    /// </summary>
    public class OpenFlowPacket : AbstractPacket, ISessionPacket {


        /**
         * http://flowgrammable.org/sdn/openflow/message-layer/
         * http://flowgrammable.org/sdn/openflow/message-layer/packetin/
         **/

        /**
         * ==OPENFLOW HEADER (8 byte)==
         * Name 	Bits 	Byte Ordering 	Constraints
         * version 	8 	- 	= 1
         * type 	8 	- 	in 0..21
         * length 	16 	MSBF 	≥ 8
         * xid 	32 	MSBF 	none
         *
         * 
         * 
         * 
         **/

        public enum Version : byte {
            v1_0 = 1,
            v1_1 = 2,
            v1_2 = 3,
            v1_3 = 4,
            v1_4 = 5
        };

        public enum OfpType {
            /* Immutable messages. */
            OFPT_HELLO = 0,  /* Symmetric message */
            OFPT_ERROR = 1,  /* Symmetric message */
            OFPT_ECHO_REQUEST = 2,  /* Symmetric message */
            OFPT_ECHO_REPLY = 3,  /* Symmetric message */
            OFPT_EXPERIMENTER = 4,  /* Symmetric message */

            /* Switch configuration messages. */
            OFPT_FEATURES_REQUEST = 5,  /* Controller/switch message */
            OFPT_FEATURES_REPLY = 6,  /* Controller/switch message */
            OFPT_GET_CONFIG_REQUEST = 7,  /* Controller/switch message */
            OFPT_GET_CONFIG_REPLY = 8,  /* Controller/switch message */
            OFPT_SET_CONFIG = 9,  /* Controller/switch message */

            /* Asynchronous messages. */
            OFPT_PACKET_IN = 10, /* Async message */
            OFPT_FLOW_REMOVED = 11, /* Async message */
            OFPT_PORT_STATUS = 12, /* Async message */

            /* Controller command messages. */
            OFPT_PACKET_OUT = 13, /* Controller/switch message */
            OFPT_FLOW_MOD = 14, /* Controller/switch message */
            OFPT_GROUP_MOD = 15, /* Controller/switch message */
            OFPT_PORT_MOD = 16, /* Controller/switch message */
            OFPT_TABLE_MOD = 17, /* Controller/switch message */

            /* Multipart messages. */
            OFPT_MULTIPART_REQUEST = 18, /* Controller/switch message */
            OFPT_MULTIPART_REPLY = 19, /* Controller/switch message */

            /* Barrier messages. */
            OFPT_BARRIER_REQUEST = 20, /* Controller/switch message */
            OFPT_BARRIER_REPLY = 21, /* Controller/switch message */

            /* Queue Configuration messages. */
            OFPT_QUEUE_GET_CONFIG_REQUEST = 22,  /* Controller/switch message */
            OFPT_QUEUE_GET_CONFIG_REPLY = 23,  /* Controller/switch message */

            /* Controller role change request messages. */
            OFPT_ROLE_REQUEST = 24, /* Controller/switch message */
            OFPT_ROLE_REPLY = 25, /* Controller/switch message */

            /* Asynchronous message configuration. */
            OFPT_GET_ASYNC_REQUEST = 26, /* Controller/switch message */
            OFPT_GET_ASYNC_REPLY = 27, /* Controller/switch message */
            OFPT_SET_ASYNC = 28, /* Controller/switch message */

            /* Meters and rate limiters configuration messages. */
            OFPT_METER_MOD = 29, /* Controller/switch message */
        };

        public static new bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            //this.version = parentFrame.Data[packetStartIndex];
            //this.type = parentFrame.Data[packetStartIndex + 1];
            result = null;
            try {
                ushort length = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
                if (length > packetEndIndex - packetStartIndex  + 1)
                    return false;
                else
                    result = new OpenFlowPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch(Exception) {
                return false;
            }
            return result != null;
        }

        private byte version, type;
        private ushort length;
        private int parsedBytesCount;
        private int nextPacketIndex;

        public bool PacketHeaderIsComplete
        {
            get
            {
                if (this.parsedBytesCount > 0)
                    return this.PacketEndIndex - this.PacketStartIndex + 1 >= this.parsedBytesCount;
                else
                    return false;
            }
        }

        public int ParsedBytesCount
        {
            get
            {
                return this.parsedBytesCount;
            }
        }

        internal OpenFlowPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "OpenFlow") {
            
            this.version = parentFrame.Data[packetStartIndex];
            this.type = parentFrame.Data[packetStartIndex + 1];
            //length = len(openFlow) + len(payload)
            this.length = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 2);
            if (this.length > PacketEndIndex - PacketStartIndex + 1)
                this.parsedBytesCount = 0;
            else { 
                this.parsedBytesCount = this.length;

                //skip 4 bytes of xid (transaction ID)
                //ushort totalLength;
                if (this.type == (byte)OfpType.OFPT_PACKET_IN) {
                    //8 byte header
                    //4 byte buffer ID
                    if (this.version == (byte)Version.v1_0) {
                        //totalLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12);
                        this.nextPacketIndex = packetStartIndex + 18;
                    }
                    else if (this.version == (byte)Version.v1_1) {
                        //totalLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 20);
                        this.nextPacketIndex = packetStartIndex + 24;
                    }
                    else if (this.version == (byte)Version.v1_2) {
                        //totalLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12);
                        ushort oxmLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 18);
                        this.nextPacketIndex = packetStartIndex + 18 + oxmLength + this.getPadding(oxmLength);
                    }
                    else if (this.version == (byte)Version.v1_3) {
                        //total length is len(payload), but the payload could be truncated, so we cannot trust it!
                        //ushort totalLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12);
                        ushort oxmLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 26);
                        //OpenFlow 1.3.0 header = 8 bytes
                        //BufferID + TotalLen + Reason + TableID + Cookie = 16 bytes
                        //
                        //match struct is oxmLength + 8-byte-align-padding
                        //final padding is 2 bytes
                        //8+16+2 = 26 + oxm + 8-byte-align-padding(oxm)
                        //this.nextPacketIndex = packetStartIndex + 34 + oxmLength;
                        //this.nextPacketIndex = packetStartIndex + 30 + oxmLength;

                        this.nextPacketIndex = packetStartIndex + 26 + oxmLength + this.getPadding(oxmLength);
                    }
                    else if (this.version == (byte)Version.v1_4) {
                        throw new NotImplementedException("OpenFlow v1.4 not implemented");
                    }
                    else
                        throw new NotImplementedException("Unknown version of OpenFlow");
                }
                else if(this.type == (byte)OfpType.OFPT_PACKET_OUT) {
                    //8 byte header
                    //4 byte buffer ID
                    if(this.version == (byte)Version.v1_0) {
                        //2 byte in port
                        ushort actionLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 14);
                        //2 bytes action length
                        this.nextPacketIndex = PacketStartIndex + 16 + actionLength;
                    }
                    else {//same structure for version 1.1 to 1.4
                        //4 byte in port
                        ushort actionLength = (ushort)Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 16);
                        //2 bytes action length
                        //6 bytes padding
                        this.nextPacketIndex = PacketStartIndex + 24 + actionLength;
                    }
                    
                }
            }
        }

        private int getPadding(int structLength) {
            //All structures are packed with padding and 8-byte aligned,
            //as checked by the assertion statement
            return (8 - (structLength % 8)) % 8;
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if (this.nextPacketIndex > 0) {
                Ethernet2Packet packet = new Ethernet2Packet(this.ParentFrame, this.nextPacketIndex, this.PacketEndIndex);
                yield return packet;
                foreach (AbstractPacket subPacket in packet.GetSubPackets(false))
                    yield return subPacket;
            }
        }

        
    }
}
