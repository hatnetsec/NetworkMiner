using System;
using System.Collections.Generic;
using System.Text;


//https://msdn.microsoft.com/en-us/library/cc246482.aspx
//https://wiki.wireshark.org/SMB2
//https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob;f=epan/dissectors/packet-smb2.c;h=a2dbc2a1bb47edcac6a5eed928a9c7fb896890a3;hb=HEAD

namespace PacketParser.Packets {
    class Smb2Packet : AbstractPacket {

        internal static uint NT_STATUS_SUCCESS = 0;
        internal static uint NT_STATUS_MORE_PROCESSING_REQUIRED = 0xc0000016;

        internal enum OP_CODE : ushort {
            NegotiateProtocol = 0x00,
            SessionSetup = 0x01,
            SessionLogoff = 0x02,
            TreeConnect = 0x03,
            TreeDisconnect = 0x04,
            Create = 0x05,
            Close = 0x06,
            Flush = 0x07,
            Read = 0x08,
            Write = 0x09,
            Lock = 0x0a,
            Ioctl = 0x0b,
            Cancel = 0x0c,
            KeepAlive = 0x0d,
            Find = 0x0e,
            Notify = 0x0f,
            GetInfo = 0x10,
            SetInfo = 0x11,
            Break = 0x12
        }

        private const uint smb2ProtocolIdentifier = 0xfe534d42;//=0xfe+SMB

        private ushort headerLength;
        private uint ntStatus;
        private ushort opCode;
        //private bool response;
        private byte flags;
        //more flags?
        private uint chainOffset;
        private ulong messageId;//unique identifier of each request, in order to match requests with responses
        private uint treeId;

        public bool IsResponse {
            get {
                return (((int)this.flags) & 0x01) == 0x01;
            }
        }

        public ulong MessageID { get { return this.messageId; } }
        public uint NtStatus { get { return this.ntStatus; } }
        public uint TreeId { get { return this.treeId; } }



        /*
        * From: https://wiki.wireshark.org/SMB2
        *
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |     0xFE      |      'S'      |      'M'      |      'B'      |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |          Header Length        |           (padding)           |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                          NT_Status                            |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |            Opcode             |            (padding)          |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |       :S:C:P:R|               |               |               |    Flags
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                          Chain Offset                         |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                        Command Sequence-                      |
        * +-+-+-+-+-+-+                                     +-+-+-+-+-+-+-+
        * |                             Number                            |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                           Process ID                          |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                            Tree ID                            |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                                                               |
        * +-+-+-+-+                    User ID                    +-+-+-+-+
        * |                                                               |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        * |                                                               |
        * +-+-+-+-+                                               +-+-+-+-+
        * |                                                               |
        * +-+-+-+-+                   Signature                   +-+-+-+-+
        * |                                                               |
        * +-+-+-+-+                                               +-+-+-+-+
        * |                                                               |
        * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        */

        internal Smb2Packet(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SMB2") {

            //BUGG: jag får inte frame 426-442 (9 TCP segment) reassemblade hit! Kan vara pga fel i NetworkTcpSessions TryAppendNextPacket?!

            uint protocolIdentifier = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex);
            if (protocolIdentifier != smb2ProtocolIdentifier) {
                throw new Exception("SMB protocol identifier is: " + protocolIdentifier.ToString("X2"));
            }
            this.headerLength = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 4, true);
            this.ntStatus = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 8, 4, true);
            this.opCode = Utils.ByteConverter.ToUInt16(parentFrame.Data, packetStartIndex + 12, true);
            this.flags = parentFrame.Data[packetStartIndex + 16];
            this.chainOffset = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 20, 4, true);
            this.messageId = Utils.ByteConverter.ToUInt64(parentFrame.Data, packetStartIndex + 24, true);//a.k.a. "Command Sequence Number"
            this.treeId = Utils.ByteConverter.ToUInt32(parentFrame.Data, packetStartIndex + 36, 4, true);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            if (!this.IsResponse || this.ntStatus == NT_STATUS_SUCCESS || this.ntStatus == NT_STATUS_MORE_PROCESSING_REQUIRED) {
                if (!this.IsResponse && this.opCode == (ushort)OP_CODE.SessionSetup) {//0x01
                    Smb2SessionSetupRequest p = new Smb2SessionSetupRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                    yield return p;
                    foreach (AbstractPacket subPacket in p.GetSubPackets(false))
                        yield return subPacket;
                }
                else if (this.IsResponse && this.opCode == (ushort)OP_CODE.SessionSetup) {//0x01
                    Smb2SessionSetupResponse p = new Smb2SessionSetupResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                    yield return p;
                    foreach (AbstractPacket subPacket in p.GetSubPackets(false))
                        yield return subPacket;
                }
                else if (!this.IsResponse && this.opCode == (ushort)OP_CODE.TreeConnect) {//0x03
                    yield return new Smb2TreeConnectRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (this.IsResponse && this.opCode == (ushort)OP_CODE.TreeConnect) {//0x03
                    yield return new Smb2TreeConnectResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (!this.IsResponse && this.opCode == (ushort)OP_CODE.Create) {//0x05
                    yield return new Smb2CreateRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (this.IsResponse && this.opCode == (ushort)OP_CODE.Create) {//0x05
                    yield return new Smb2CreateResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (!this.IsResponse && this.opCode == (ushort)OP_CODE.Close) {//0x06
                    yield return new Smb2CloseRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (this.IsResponse && this.opCode == (ushort)OP_CODE.Close) {//0x06
                    yield return new Smb2CloseResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (!this.IsResponse && this.opCode == (short)OP_CODE.Read) { //0x08
                    yield return new Smb2ReadRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (this.IsResponse && this.opCode == (short)OP_CODE.Read) { //0x08
                    yield return new Smb2ReadResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (!this.IsResponse && this.opCode == (ushort)OP_CODE.Write) {//0x09
                    yield return new Smb2WriteRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (!this.IsResponse && this.opCode == (short)OP_CODE.Find) { //0x0e
                    yield return new Smb2FindRequest(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
                else if (this.IsResponse && this.opCode == (short)OP_CODE.Find) { //0x0e
                    yield return new Smb2FindResponse(this, this.PacketStartIndex + this.headerLength, this.PacketEndIndex);
                }
            }

            if (this.chainOffset > 0) {
                Smb2Packet chainedPacket = new Smb2Packet(this.ParentFrame, this.PacketStartIndex + (int)this.chainOffset, this.PacketEndIndex);
                yield return chainedPacket;
                foreach (AbstractPacket subPacket in chainedPacket.GetSubPackets(false))
                    yield return subPacket;
            }
        }

        internal static Guid ReadSmb2FileId(byte[] data, int offset) {
            byte[] guidBytes = new byte[16];
            Array.Copy(data, offset, guidBytes, 0, 16);
            return new Guid(guidBytes);
        }

        internal static string ReadSmb2FileIdString(byte[] data, int offset) {
            //FileId (16 bytes): An SMB2_FILEID. Use Wireshark format convension 4-2-2-2-6: ffffffff-ffff-ffff-ffff-ffffffffffff (hex) == GUID
            StringBuilder fileId = new StringBuilder();
            //Persistent
            for (int i = 0; i < 4; i++)
                fileId.Append(data[offset + i].ToString("x2"));
            fileId.Append("-");
            for (int i = 0; i < 2; i++)
                fileId.Append(data[offset + 4 + i].ToString("x2"));
            fileId.Append("-");
            for (int i = 0; i < 2; i++)
                fileId.Append(data[offset + 6 + i].ToString("x2"));

            fileId.Append("-");
            //Volatile
            for (int i = 0; i < 2; i++)
                fileId.Append(data[offset + 8 + i].ToString("x2"));
            fileId.Append("-");
            for (int i = 0; i < 6; i++)
                fileId.Append(data[offset + 10 + i].ToString("x2"));
            return fileId.ToString();
        }

        internal static DateTime ReadFileTime(byte[] data, int offset) {
#if DEBUG
            if (data.Length < offset + 8)
                System.Diagnostics.Debugger.Break();
#endif
            long ticksSince1600 = BitConverter.ToInt64(data, offset);
            if (ticksSince1600 > 0)
                return new DateTime(ticksSince1600).AddYears(1600);
            else
                return DateTime.MinValue;
        }


        internal abstract class Smb2Command : AbstractPacket {
            private Smb2Packet smb2Packet;

            public Smb2Packet Smb2Packet { get { return this.smb2Packet; } }

            internal Smb2Command(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex, string commandName)
                    : base(smb2Packet.ParentFrame, packetStartIndex, packetEndIndex, commandName) {
                this.smb2Packet = smb2Packet;
            }
        }

        internal class Smb2SessionSetupRequest : Smb2Command { //0x01

            private ushort blobOffset;
            private ushort blobLength;

            internal Smb2SessionSetupRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Session Setup Request") {
                this.blobOffset = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 12, true);
                this.blobLength = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 14, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;

                if (this.blobLength > 0 && this.blobOffset > 0) {
                    SmbPacket.SecurityBlob securityBlob = new SmbPacket.SecurityBlob(this.ParentFrame, base.Smb2Packet.PacketStartIndex + this.blobOffset, this.PacketEndIndex);
                    if (securityBlob != null) {
                        yield return securityBlob;

                        foreach (AbstractPacket subPacket in securityBlob.GetSubPackets(false))
                            yield return subPacket;
                    }
                }
            }
        }

        internal class Smb2SessionSetupResponse : Smb2Command { //0x01

            private ushort blobOffset;
            private ushort blobLength;

            internal Smb2SessionSetupResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Session Setup Response") {
                this.blobOffset = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 4, true);
                this.blobLength = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 6, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;

                if (this.blobLength > 0 && this.blobOffset > 0) {
                    SmbPacket.SecurityBlob securityBlob = new SmbPacket.SecurityBlob(this.ParentFrame, base.Smb2Packet.PacketStartIndex + this.blobOffset, this.PacketEndIndex);
                    if (securityBlob != null) {
                        yield return securityBlob;

                        foreach (AbstractPacket subPacket in securityBlob.GetSubPackets(false))
                            yield return subPacket;
                    }
                }
            }
        }

        internal class Smb2TreeConnectRequest : Smb2Command { //0x03
            private ushort nameOffset; //NameOffset (2 bytes)
            private ushort nameLength; //NameLength (2 bytes)
            private string shareName;

            public string ShareName { get { return this.shareName; } }

            internal Smb2TreeConnectRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Tree Connect Request") {
                this.nameOffset = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 4, true);
                this.nameLength = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 6, true);
                this.shareName = Utils.ByteConverter.ReadString(this.ParentFrame.Data, smb2Packet.PacketStartIndex + this.nameOffset, this.nameLength, true, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }
        internal class Smb2TreeConnectResponse : Smb2Command { //0x03

            internal Smb2TreeConnectResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Tree Connect Response") {
                if (base.Smb2Packet.ntStatus == NT_STATUS_SUCCESS) {
                    //success
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2CreateResponse : Smb2Command { //0x05

            private const short VALID_STRUCTURE_SIZE = 0x0059;

            private short structureSize;
            private DateTime creationTime;
            private DateTime lastAccessTime;
            private DateTime lastWriteTime;
            private DateTime changeTime;
            private Guid fileId;

            public bool IsValidCreateResponse { get { return this.structureSize == VALID_STRUCTURE_SIZE; } }
            public DateTime CreationTime { get { return this.creationTime; } }
            public DateTime LastAccessTIme { get { return this.lastAccessTime; } }
            public DateTime LastWriteTime { get { return this.lastWriteTime; } }
            public DateTime ChangeTime { get { return this.changeTime; } }
            public Guid FileID { get { return this.fileId; } }

            internal Smb2CreateResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Create Response") {
                this.structureSize = BitConverter.ToInt16(this.ParentFrame.Data, packetStartIndex);
                if (this.structureSize == VALID_STRUCTURE_SIZE) {
                    this.creationTime = ReadFileTime(this.ParentFrame.Data, packetStartIndex + 8);
                    this.lastAccessTime = ReadFileTime(this.ParentFrame.Data, packetStartIndex + 16);
                    this.lastWriteTime = ReadFileTime(this.ParentFrame.Data, packetStartIndex + 24);
                    this.changeTime = ReadFileTime(this.ParentFrame.Data, packetStartIndex + 32);
                    this.fileId = ReadSmb2FileId(this.ParentFrame.Data, packetStartIndex + 64);
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2CreateRequest : Smb2Command { //0x05
            private ushort nameOffset; //NameOffset (2 bytes)
            private ushort nameLength; //NameLength (2 bytes)
            private string fileName;

            public string FileName { get { return this.fileName; } }

            internal Smb2CreateRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Create") {
                this.nameOffset = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 44, true);
                this.nameLength = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 46, true);
                this.fileName = Utils.ByteConverter.ReadString(this.ParentFrame.Data, smb2Packet.PacketStartIndex + this.nameOffset, this.nameLength, true, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2ReadRequest : Smb2Command { //0x08
            private uint readLength;
            private long fileOffset;
            private Guid fileId;

            public long FileOffset { get { return this.fileOffset; } }
            public Guid FileId { get { return this.fileId; } }

            internal Smb2ReadRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Read") {
                this.readLength = BitConverter.ToUInt32(this.ParentFrame.Data, PacketStartIndex + 4);
                this.fileOffset = BitConverter.ToInt64(this.ParentFrame.Data, PacketStartIndex + 8);
                this.fileId = ReadSmb2FileId(this.ParentFrame.Data, packetStartIndex + 16);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2ReadResponse : Smb2Command {
            private ushort dataOffset; //DataOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the data being read.
            private uint dataLength; //Length (4 bytes): The length of the data being read, in bytes. The length of the data being read may be zero bytes.
            private uint readRemaining;
            byte[] fileData;

            public byte[] FileData { get { return this.fileData; } }

            internal Smb2ReadResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Read Response") {
                this.dataOffset = BitConverter.ToUInt16(this.ParentFrame.Data, PacketStartIndex + 2);
                this.dataLength = BitConverter.ToUInt32(this.ParentFrame.Data, PacketStartIndex + 4);
                this.readRemaining = BitConverter.ToUInt32(this.ParentFrame.Data, PacketStartIndex + 8);

                this.fileData = new byte[this.dataLength];
                Array.Copy(this.ParentFrame.Data, smb2Packet.PacketStartIndex + this.dataOffset, this.fileData, 0, this.dataLength);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2WriteRequest : Smb2Command {
            //https://wiki.wireshark.org/SMB2/Write

            private ushort dataOffset; //DataOffset (2 bytes): The offset, in bytes, from the beginning of the SMB2 header to the data being written.
            private uint dataLength; //Length (4 bytes): The length of the data being written, in bytes. The length of the data being written may be zero bytes.
            private long fileOffset; //Offset (8 bytes): The offset, in bytes, of where to write the data in the destination file. If the write is being executed on a pipe, the Offset MUST be set to 0 by the client and MUST be ignored by the server.
            private Guid fileId; //FileId (16 bytes): An SMB2_FILEID. Use Wireshark GUID format convension 4-2-2-2-6: ffffffff-ffff-ffff-ffff-ffffffffffff (hex)
            private byte[] fileData;

            public long FileOffset { get { return this.fileOffset; } }
            public Guid FileID { get { return this.fileId; } }
            public byte[] FileData { get { return this.fileData; } }

            internal Smb2WriteRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Write") {
                this.dataOffset = Utils.ByteConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex + 2, true);
                this.dataLength = Utils.ByteConverter.ToUInt32(this.ParentFrame.Data, packetStartIndex + 4, 4, true);
                this.fileOffset = BitConverter.ToInt64(this.ParentFrame.Data, PacketStartIndex + 8);
                //this.fileOffset = Utils.ByteConverter.ToUInt64(this.ParentFrame.Data, packetStartIndex + 8, true);

                this.fileId = ReadSmb2FileId(this.ParentFrame.Data, packetStartIndex + 16);

                this.fileData = new byte[this.dataLength];
                Array.Copy(this.ParentFrame.Data, smb2Packet.PacketStartIndex + this.dataOffset, this.fileData, 0, this.dataLength);

            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        /*
        internal class Smb2SetInfoRequest : Smb2Command {
            private ulong? endOfFile = null;

            internal Smb2SetInfoRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet.ParentFrame, packetStartIndex, packetEndIndex, "SMB2 SetInfo") {
                //https://wiki.wireshark.org/SMB2/SetInfo
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }*/
        internal class Smb2CloseRequest : Smb2Command {
            private Guid fileId;

            public Guid FileID { get { return this.fileId; } }

            internal Smb2CloseRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Close") {
                this.fileId = ReadSmb2FileId(this.ParentFrame.Data, packetStartIndex + 8);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2CloseResponse : Smb2Command {
            private long endOfFile;//file size

            /// <summary>
            /// File size of FileID in request
            /// </summary>
            public long EndOfFile { get { return this.endOfFile; } }

            internal Smb2CloseResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Close Response") {
                if (smb2Packet.ntStatus == NT_STATUS_SUCCESS) {//STATUS_SUCCESS
                    ushort structureSize = BitConverter.ToUInt16(this.ParentFrame.Data, packetStartIndex);
                    if (structureSize == 0x3c) {
                        //if status is success
                        this.endOfFile = BitConverter.ToInt64(this.ParentFrame.Data, packetStartIndex + 48);
                    }
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2FindRequest : Smb2Command {//Command 0x0e

            public enum InfoLevelEnum : byte {
                DIRECTORY_INFO = 0x01,
                FULL_DIRECTORY_INFO = 0x02,
                BOTH_DIRECTORY_INFO = 0x03,
                INDEX_SPECIFIED = 0x04,
                NAME_INFO = 0x0C,
                ID_BOTH_DIRECTORY_INFO = 0x25,
                ID_FULL_DIRECTORY_INFO = 0x26
            }

            private string searchPattern;
            private byte infoLevel;

            public string SearchPattern { get { return this.searchPattern; } }
            public byte InfoLevel { get { return this.infoLevel; } }//in lack of a better name I'm using wireshark's "InfoLevel" name. This one specifies the format of the respones

            internal Smb2FindRequest(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Find Request") {

                this.infoLevel = this.ParentFrame.Data[PacketStartIndex + 2];

                ushort searchPatternOffset = BitConverter.ToUInt16(this.ParentFrame.Data, PacketStartIndex + 24);//offset from start of SMB2 packet
                ushort searchPatternLength = BitConverter.ToUInt16(this.ParentFrame.Data, PacketStartIndex + 26);

                this.searchPattern = Utils.ByteConverter.ReadString(this.ParentFrame.Data, base.Smb2Packet.PacketStartIndex + searchPatternOffset, searchPatternLength, true, true);
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2FindResponse : Smb2Command {//Command 0x0e
            private List<Smb2FileInfo> fileInfoList;

            public List<Smb2FileInfo> FileInfoList { get { return this.fileInfoList; } }

            internal Smb2FindResponse(Smb2Packet smb2Packet, int packetStartIndex, int packetEndIndex)
            : base(smb2Packet, packetStartIndex, packetEndIndex, "SMB2 Find Response") {
                ushort responseOffset = BitConverter.ToUInt16(this.ParentFrame.Data, PacketStartIndex + 2);
                int responseSize = BitConverter.ToInt32(this.ParentFrame.Data, PacketStartIndex + 4);


                this.fileInfoList = new List<Smb2FileInfo>();
                int index = packetStartIndex + 8;
                int responseEndIndex = index + responseSize;
                while (index < packetEndIndex) {
                    Smb2FileInfo fileInfo = new Smb2FileInfo(this.ParentFrame.Data, index, responseEndIndex);
                    fileInfoList.Add(fileInfo);
                    if (fileInfo.NextOffset > 0)
                        index += fileInfo.NextOffset;
                    else
                        break;
                }
            }

            public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
                if (includeSelfReference)
                    yield return this;
            }
        }

        internal class Smb2FileInfo {
            //https://wiki.wireshark.org/SMB2/SMB2_FILE_INFO_STANDARD
            private int nextOffset;
            private byte[] data;

            public int NextOffset { get { return this.nextOffset; } }
            public byte[] Data { get { return this.data; } }

            internal Smb2FileInfo(byte[] data, int startIndex, int responseEndIndex) {
                this.nextOffset = BitConverter.ToInt32(data, startIndex);
                int blobSize = this.nextOffset;
                if (blobSize == 0)//NextOffset is 0 for the last entry to denote that there are no more entries trailing
                    blobSize = Math.Min(data.Length - startIndex, responseEndIndex - startIndex);
                if (blobSize >= 0) {
                    this.data = new byte[blobSize];
                    Array.Copy(data, startIndex, this.data, 0, blobSize);
                }
            }

        }
        //Almost the same as Smb2FileInfoIdBothDirectoryInfo (see smb2.find.infolevel), but without the 8 byte file ID (longNameIndex is 10 bytes earlier)
        internal class Smb2FileNameInfo : Smb2FileInfo {
            //https://wiki.wireshark.org/SMB2/SMB2_FILE_INFO_STANDARD
            private string filename;

            public string Filename { get { return this.filename; } }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="data"></param>
            /// <param name="startIndex"></param>
            /// <param name="infoLevel">Must be 12 (SMB2_FIND_NAME_INFO)</param>
            internal Smb2FileNameInfo(byte[] data, int startIndex, int responseEndIndex, byte infoLevel) : base(data, startIndex, responseEndIndex) {

                /**
                    SMB2_FIND_DIRECTORY_INFO         0x01
                    SMB2_FIND_FULL_DIRECTORY_INFO    0x02
                    SMB2_FIND_BOTH_DIRECTORY_INFO    0x03
                    SMB2_FIND_INDEX_SPECIFIED        0x04
                    SMB2_FIND_NAME_INFO              0x0C - SUPPORTED HERE
                    SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25
                    SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26
                    **/

                int longNameLength = BitConverter.ToInt32(data, startIndex + 8);
                if (longNameLength > 0) {
                    this.filename = Utils.ByteConverter.ReadString(data, startIndex + 8 + 4, longNameLength, true, true);
#if DEBUG
                    if (this.filename.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0) {
                        System.Diagnostics.Debugger.Break();
                    }
#endif
                }
                else
                    this.filename = "";
            }
        }

        //Almost the same as Smb2FileIdBothDirectoryInfo (see smb2.find.infolevel), but without the 8 byte file ID (longNameIndex is 10 bytes earlier)
        internal class Smb2FileBothDirectoryInfo : Smb2FileInfo {
            //https://wiki.wireshark.org/SMB2/SMB2_FILE_INFO_STANDARD
            private DateTime creationTime;
            private DateTime lastAccessTime;
            private DateTime lastWriteTime;
            private DateTime lastAttributeChangeTime;
            private string filename;


            public DateTime Created { get { return this.creationTime; } }
            public DateTime Modified { get { return this.lastWriteTime; } }
            public DateTime Accessed { get { return this.lastAccessTime; } }
            public DateTime AttributeChanged { get { return this.lastAttributeChangeTime; } }
            public string Filename { get { return this.filename; } }

            /// <summary>
            /// 
            /// </summary>
            /// <param name="data"></param>
            /// <param name="startIndex"></param>
            /// <param name="infoLevel">Must be 3 (BOTH_DIRECTORY_INFO) or 37 (ID_BOTH_DIRECTORY_INFO)</param>
            internal Smb2FileBothDirectoryInfo(byte[] data, int startIndex, int responseEndIndex, byte infoLevel) : base(data, startIndex, responseEndIndex) {
                this.creationTime = ReadFileTime(data, startIndex + 8);
                this.lastAccessTime = ReadFileTime(data, startIndex + 16);
                this.lastWriteTime = ReadFileTime(data, startIndex + 24);
                this.lastAttributeChangeTime = ReadFileTime(data, startIndex + 32);

                int longNameLength = BitConverter.ToInt32(data, startIndex + 20 + 32 + 8);
                if (longNameLength > 0) {
                    byte shortNameLength = data[startIndex + 20 + 32 + 16];
                    //int longNameIndex = startIndex + 20 + 32 + 16 + 4 + shortNameLength + 32;
                    /**
                    SMB2_FIND_DIRECTORY_INFO         0x01
                    SMB2_FIND_FULL_DIRECTORY_INFO    0x02
                    SMB2_FIND_BOTH_DIRECTORY_INFO    0x03 - SUPPORTED HERE
                    SMB2_FIND_INDEX_SPECIFIED        0x04
                    SMB2_FIND_NAME_INFO              0x0C
                    SMB2_FIND_ID_BOTH_DIRECTORY_INFO 0x25 - SUPPORTED HERE
                    SMB2_FIND_ID_FULL_DIRECTORY_INFO 0x26
                    **/
                    int longNameIndex = -1;
                    if (infoLevel == 0x03) //SMB2_FIND_BOTH_DIRECTORY_INFO
                        longNameIndex = startIndex + 20 + 32 + 16 + 4 + 22;
                    else if (infoLevel == 0x25) //SMB2_FIND_ID_BOTH_DIRECTORY_INFO
                        longNameIndex = startIndex + 20 + 32 + 16 + 4 + 32;

                    if (shortNameLength > 24) {//there is probably no short name here, probably a long name string
                        int newLongNameIndex = startIndex + 20 + 32 + 16;
                        if (Utils.ByteConverter.ReadString(data, newLongNameIndex, longNameLength, true, true).IndexOfAny(System.IO.Path.GetInvalidPathChars()) < 0)
                            longNameIndex = newLongNameIndex;
                    }
                    if (longNameIndex > 0) {
                        this.filename = Utils.ByteConverter.ReadString(data, longNameIndex, longNameLength, true, true);
#if DEBUG
                        if (this.filename.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0) {
                            System.Diagnostics.Debugger.Break();
                        }
#endif
                    }
                    else
                        this.filename = "";
                }
                else
                    this.filename = "";

            }
        }
    }
}
