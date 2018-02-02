using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class SocksPacket : AbstractPacket, ISessionPacket {
        //https://www.ietf.org/rfc/rfc1928.txt
        //https://tools.ietf.org/html/rfc1929   Username/Password Authentication for SOCKS V5

        public enum ATYP:byte {
            IPv4 = 0x01,
            DOMAINNAME = 0x03,
            IPv6 = 0x04,
            None = 0xff
        }

        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {
            result = null;
            if (!clientToServer && packetEndIndex - packetStartIndex == 1 && parentFrame.Data[packetStartIndex] == 1 && parentFrame.Data[packetStartIndex + 1] == 0) {
                result = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);//RFC1929 Initial negotiation response
                return true;
            }
            if (parentFrame.Data.Length < packetStartIndex + 2)
                return false;

            if (clientToServer && isLikelyInitialUsernamePasswordNegotiation(parentFrame, packetStartIndex, packetEndIndex)) {
                try {
                    SocksPacket socksPacket = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                    if (socksPacket.PacketHeaderIsComplete) {
                        result = socksPacket;
                        return true;
                    }
                    else
                        return false;
                }
                catch { return false; }
            }

            if (parentFrame.Data[packetStartIndex] < 4 || parentFrame.Data[packetStartIndex] > 5)
                return false;
            if (clientToServer) {
                byte nMethodsOrCmd = parentFrame.Data[packetStartIndex + 1];
                if (packetEndIndex - packetStartIndex == nMethodsOrCmd + 1) {
                    //version identifier/method selection message
                    try {
                        SocksPacket socksPacket = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        if (socksPacket.PacketHeaderIsComplete) {
                            result = socksPacket;
                            return true;
                        }
                        else
                            return false;
                    }
                    catch { return false; }
                }
                else if (parentFrame.Data.Length > packetStartIndex + 6) {
                    if (isLikelySocksRequestOrReply(parentFrame, packetStartIndex, packetEndIndex)) {
                        try {
                            SocksPacket socksPacket = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                            if (socksPacket.PacketHeaderIsComplete) {
                                result = socksPacket;
                                return true;
                            }
                            else
                                return false;
                        }
                        catch { return false; }
                    }
                    else
                        return false;
                }
                else
                    return false;
            }
            else {
                //server to client
                if (packetEndIndex - packetStartIndex == 1) {
                    //METHOD selection message
                    try {
                        SocksPacket socksPacket = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                        if (socksPacket.PacketHeaderIsComplete) {
                            result = socksPacket;
                            return true;
                        }
                        else
                            return false;
                    }
                    catch { return false; }
                }
                else if (packetEndIndex - packetStartIndex > 6) {
                    if (isLikelySocksRequestOrReply(parentFrame, packetStartIndex, packetEndIndex)) {
                        try {
                            SocksPacket socksPacket = new SocksPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                            if (socksPacket.PacketHeaderIsComplete) {
                                result = socksPacket;
                                return true;
                            }
                            else
                                return false;
                        }
                        catch { return false; }
                    }
                    else
                        return false;
                }
                else
                    return false;
            }
        }

        private static bool isLikelyInitialUsernamePasswordNegotiation(Frame parentFrame, int packetStartIndex, int packetEndIndex) {
            /**
             * Username/Password subnegotiation
             *  +----+------+----------+------+----------+
             *  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
             *  +----+------+----------+------+----------+
             *  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
             *  +----+------+----------+------+----------+
             *  The VER field contains the current version of the subnegotiation, which is X'01'
             **/

            int packetLength = packetEndIndex - packetStartIndex + 1;

            if (parentFrame.Data[packetStartIndex] != 1)
                return false;
            if (packetLength < 5)
                return false;
            byte ulen = parentFrame.Data[packetStartIndex + 1];
            if (packetLength < ulen + 4)
                return false;
            byte plen = parentFrame.Data[packetStartIndex + ulen + 2];
            if (packetLength == ulen + plen + 3)
                return true;
            else
                return false;
        }

        private static bool isLikelySocksRequestOrReply(Frame parentFrame, int packetStartIndex, int packetEndIndex) {
            if (parentFrame.Data[packetStartIndex + 2] != 0)
                return false;
            byte atyp = parentFrame.Data[packetStartIndex + 3];
            if (atyp == (byte)ATYP.IPv4) {
                if (packetEndIndex - packetStartIndex != 9)
                    return false;
            }
            else if (atyp == (byte)ATYP.IPv6) {
                if (packetEndIndex - packetStartIndex != 21)
                    return false;
            }
            else if (atyp == (byte)ATYP.DOMAINNAME) {
                if (packetEndIndex - packetStartIndex != parentFrame.Data[packetStartIndex + 4] + 6)
                    return false;
            }
            else
                return false;
            return true;//all tests passed

        }

        private bool clientToServer;
        private int parsedBytesCount;
        private byte socksVersion;
        private byte commandOrReply;
        private ATYP atyp;
        private string domainName;
        private System.Net.IPAddress ipAddress = null;
        private ushort port;
        private string username, password;

        public bool PacketHeaderIsComplete { get { return this.parsedBytesCount > 0; } }

        public int ParsedBytesCount
        {
            get
            {
                return this.parsedBytesCount;
            }
        }

        public bool ClientToServer { get { return this.clientToServer; } }

        public byte CommandOrReply { get { return this.commandOrReply; } }
        public ATYP ATyp { get { return this.atyp; } }
        public System.Net.IPAddress IpAddress { get { return this.ipAddress; } }
        public string DomainName { get { return this.domainName; } }
        public ushort Port { get { return this.port; } }
        public string Username { get { return this.username; } }
        public string Password { get { return this.password; } }
        
        internal SocksPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
        : base(parentFrame, packetStartIndex, packetEndIndex, "SOCKS") {
            this.clientToServer = clientToServer;
            this.parsedBytesCount = 0;
            this.atyp = ATYP.None;

            int index = PacketStartIndex;

            if (clientToServer) {
                /**
                 * version identifier/method selection message. Example: 050100
                 * +----+----------+----------+
                 * |VER | NMETHODS | METHODS  |
                 * +----+----------+----------+
                 * | 1  |    1     | 1 to 255 |
                 * +----+----------+----------+
                 * o  X'00' NO AUTHENTICATION REQUIRED
                 * o  X'01' GSSAPI
                 * o  X'02' USERNAME/PASSWORD
                 * o  X'03' to X'7F' IANA ASSIGNED
                 * o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
                 * o  X'FF' NO ACCEPTABLE METHODS
                 * 
                 * SOCKS request. Example 0501000314636865636b2e746f7270726f6a6563742e6f726701bb
                 * +----+-----+-------+------+----------+----------+
                 * |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
                 * +----+-----+-------+------+----------+----------+
                 * | 1  |  1  | X'00' |  1   | Variable |    2     |
                 * +----+-----+-------+------+----------+----------+
                 * o  VER    protocol version: X'05'
                 * o  CMD
                 *      o  CONNECT X'01'
                 *      o  BIND X'02'
                 *      o  UDP ASSOCIATE X'03'
                 * o  RSV    RESERVED
                 * o  ATYP   address type of following address
                 *      o  IP V4 address: X'01'
                 *      o  DOMAINNAME: X'03'
                 *      o  IP V6 address: X'04'
                 * o  DST.ADDR       desired destination address
                 * o  DST.PORT desired destination port in network octet order
                 */

                /**
                 * Username/Password subnegotiation
                 *  +----+------+----------+------+----------+
                 *  |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
                 *  +----+------+----------+------+----------+
                 *  | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
                 *  +----+------+----------+------+----------+
                 *  The VER field contains the current version of the subnegotiation, which is X'01'
                 **/


                //allow unix style line feeds (0x0a) from clients
                this.socksVersion = parentFrame.Data[index++];
                byte nMethodsOrCmdOrUlen = parentFrame.Data[index++];
                byte method1OrRsv = parentFrame.Data[index++];
                if (method1OrRsv != 0 && packetEndIndex - packetStartIndex == nMethodsOrCmdOrUlen + 1) {
                    //version identifier/method selection message
                    index = packetEndIndex + 1;//skip the data
                }
                else if (isLikelyInitialUsernamePasswordNegotiation(parentFrame, packetStartIndex, packetEndIndex)) {
                    //Username/Password subnegotiation
                    byte userLenght = parentFrame.Data[packetStartIndex + 1];
                    this.username = System.Text.Encoding.ASCII.GetString(parentFrame.Data, PacketStartIndex + 2, userLenght);
                    byte passLength = parentFrame.Data[packetStartIndex + userLenght + 2];
                    this.password = System.Text.Encoding.ASCII.GetString(parentFrame.Data, PacketStartIndex + userLenght + 3, passLength);
                    index = packetEndIndex + 1;
                }
                else if (method1OrRsv == 0) {
                    //SOCKS request
                    this.commandOrReply = nMethodsOrCmdOrUlen;
                    byte atyp = parentFrame.Data[index++];
                    if (Enum.IsDefined(typeof(ATYP), atyp)) {
                        this.atyp = (ATYP)atyp;
                        index += this.extractAddressAndPort(parentFrame.Data, index, this.atyp);
                    }
                    else
                        index = packetStartIndex;

                }

            }
            else {
                if (base.PacketLength == 2 && parentFrame.Data[packetStartIndex] == 1 && parentFrame.Data[packetStartIndex + 1] == 0) {
                    //rfc1929 initial negotiation response
                    index = packetStartIndex + 2;
                }
                else {
                    /**
                     * METHOD selection message:
                     * +----+--------+
                     * |VER | METHOD |
                     * +----+--------+
                     * | 1  |   1    |
                     * +----+--------+
                     * 
                     * SOCKS reply
                     * +----+-----+-------+------+----------+----------+
                     * |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
                     * +----+-----+-------+------+----------+----------+
                     * | 1  |  1  | X'00' |  1   | Variable |    2     |
                     * +----+-----+-------+------+----------+----------+
                     **/
                    this.socksVersion = parentFrame.Data[index++];
                    if (packetEndIndex - packetStartIndex == 1) {
                        //METHOD selection message
                        index++;//just skip past the method selection
                    }
                    else if (base.PacketLength > 6 && parentFrame.Data[packetStartIndex + 2] == 0) {
                        //SOCKS reply
                        this.commandOrReply = parentFrame.Data[packetStartIndex + 1];
                        byte atyp = parentFrame.Data[packetStartIndex + 3];
                        if (Enum.IsDefined(typeof(ATYP), atyp)) {
                            this.atyp = (ATYP)atyp;
                            index += 3;
                            index += this.extractAddressAndPort(parentFrame.Data, index, this.atyp);
                        }
                        else index = packetStartIndex;
                    }
                    else
                        index = packetStartIndex;//nothing to parse

                }
            }
            this.parsedBytesCount = index - packetStartIndex;
        }

        private int extractAddressAndPort(byte[] data, int index, ATYP atyp) {
            if (atyp == ATYP.DOMAINNAME) {
                /**
                 * the address field contains a fully-qualified domain name.  The first
                 * octet of the address field contains the number of octets of name that
                 * follow, there is no terminating NUL octet.
                 **/
                //read as a pascal string
                byte length = data[index];
                //we might wanna add support for punycode here to hanlde characters like едц
                this.domainName = System.Text.Encoding.ASCII.GetString(data, index + 1, length);
                this.port = Utils.ByteConverter.ToUInt16(data, index + length + 1, false);
                return length + 3;
            }
            else if (atyp == ATYP.IPv4 || atyp == ATYP.IPv6) {
                byte[] ipBytes;
                if (atyp == ATYP.IPv4)
                    ipBytes = new byte[4];//the address is a version-4 IP address, with a length of 4 octets
                else
                    ipBytes = new byte[16];//the address is a version-6 IP address, with a length of 16 octets.
                Array.Copy(data, index, ipBytes, 0, ipBytes.Length);
                this.ipAddress = new System.Net.IPAddress(ipBytes);
                this.port = Utils.ByteConverter.ToUInt16(data, index + ipBytes.Length, false);
                return ipBytes.Length + 2;
            }
            else
                return 0;
        }
        

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if (includeSelfReference)
                yield return this;
            //yield break;
        }
    }
}
