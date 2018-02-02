using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class TabularDataStreamPacket : AbstractPacket, ISessionPacket {
        //http://www.freetds.org/tds.html

        //http://msdn.microsoft.com/en-us/library/cc448535.aspx
        internal enum PacketTypes : byte { SqlQuery=1, PreTds7Login=2, RemoteProcedureCall=3, TableResponse=4, AttentionSignal=6, BulkLoadData=7, TransactionManagerRequest=14, Tds7Login=16, SspiMessage=17, PreLoginMessage=18 }

        public byte PacketType { get { return this.packetType; } }
        public bool IsLastPacket { get { return this.IsLastPacket; } }
        public ushort PacketSize { get { return this.PacketSize; } }

        //SQL Query (0x01)
        public string Query { get { return this.query; } }

        //tds7Login (0x10)
        public string ClientHostname { get { return this.clientHostname; } }
        public string Username { get { return this.username; } }
        public string Password { get { return this.password; } }
        public string AppName { get { return this.appname; } }
        public string ServerHostname { get { return this.serverHostname; } }
        public string LibraryName { get { return this.libraryName; } }
        public string DatabaseName { get { return this.databaseName; } }

        private byte packetType;
        private bool isLastPacket;
        private ushort packetSize;

        //SQL Query (0x01)
        private string query;

        //tds7Login (0x10)
        private string clientHostname;
        private string username;
        private string password;
        private string appname;
        private string serverHostname;
        //skip some data
        private string libraryName;
        private string databaseName;



        internal TabularDataStreamPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "Tabular Data Stream (SQL)") {
            this.packetType=parentFrame.Data[PacketStartIndex];
            this.isLastPacket=parentFrame.Data[PacketStartIndex+1]==0x01;//just true or false
            this.packetSize = Utils.ByteConverter.ToUInt16(parentFrame.Data, PacketStartIndex + 2);
            //skip 4 bytes
            int subPacketIndex=PacketStartIndex+4+4;
            if(this.packetType==(byte)PacketTypes.SqlQuery) {//0x01
                this.query = Utils.ByteConverter.ReadString(parentFrame.Data, subPacketIndex, Math.Min(PacketEndIndex - subPacketIndex + 1, this.packetSize - 8), true, true);
            }
            if(this.packetType==(byte)PacketTypes.Tds7Login) {//0x10
                this.clientHostname = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 36, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 38, true),
                    true,
                    true);
                this.username = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 40, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 42, true),
                    true,
                    true);
                int tmp = subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 44, true);
                this.password = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    ref tmp,
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 46, true),
                    true,
                    true,
                    Utils.ByteConverter.Encoding.TDS_password);
                this.appname = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 48, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 50, true),
                    true,
                    true);
                this.serverHostname = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 52, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 54, true),
                    true,
                    true);
                //skip some fields
                this.libraryName = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 60, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 62, true),
                    true,
                    true);
                //skip language
                this.databaseName = Utils.ByteConverter.ReadString(
                    parentFrame.Data,
                    subPacketIndex + Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 68, true),
                    2 * Utils.ByteConverter.ToUInt16(parentFrame.Data, subPacketIndex + 70, true),
                    true,
                    true);

                if (!this.ParentFrame.QuickParse) {
                    if (this.clientHostname.Length > 0)
                        base.Attributes.Add("SQL client hostname", this.clientHostname);
                    if (this.username.Length > 0)
                        base.Attributes.Add("SQL username", this.username);
                    if (this.password.Length > 0)
                        base.Attributes.Add("SQL password", this.password);
                    if (this.appname.Length > 0)
                        base.Attributes.Add("App name", this.appname);
                    if (this.serverHostname.Length > 0)
                        base.Attributes.Add("SQL server", this.serverHostname);
                    if (this.libraryName.Length > 0)
                        base.Attributes.Add("SQL library", this.libraryName);
                    if (this.databaseName.Length > 0)
                        base.Attributes.Add("Database name", this.databaseName);
                }
            }


        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            yield break;
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            get { return base.PacketLength>=this.packetSize; }
        }

        public int ParsedBytesCount { get { return base.PacketLength; } }

        #endregion

    }
}
