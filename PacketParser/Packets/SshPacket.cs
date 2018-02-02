//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {
    class SshPacket : AbstractPacket, ISessionPacket {
        private string sshVersion;
        private string sshApplication;

        public string SshVersion { get { return this.sshVersion; } }
        public string SshApplication { get { return this.sshApplication; } }

        new public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, out AbstractPacket result) {
            result=null;

            //Do stuff
            System.Text.RegularExpressions.Regex regEx=new System.Text.RegularExpressions.Regex("^SSH-[12].[0-9]");
            if(packetEndIndex-packetStartIndex>100)
                return false;
            else if(packetEndIndex-packetStartIndex<8)
                return false;
            
            //int i=packetStartIndex;
            string str = Utils.ByteConverter.ReadString(parentFrame.Data, packetStartIndex, packetEndIndex - packetStartIndex);
            if(!regEx.IsMatch(str))
                return false;

            try {
                result=new SshPacket(parentFrame, packetStartIndex, packetEndIndex);
            }
            catch {
                result=null;
            }


            if(result==null)
                return false;
            else
                return true;
        }

        //this one will just implement the SSH Protocol Version Identification as in http://java-hush.sourceforge.net/prot-1.5.html#version 
        private SshPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex)
            : base(parentFrame, packetStartIndex, packetEndIndex, "SSH") {
            this.sshVersion=null;
            this.sshApplication=null;
            /**
             * After the socket is opened, the server sends an identification string,
             * which is of the form "SSH-<protocolmajor>.<protocolminor>-<version>\n",
             * where <protocolmajor> and <protocolminor> are integers and specify the
             * protocol version number (not software distribution version).
             * <version>is server side software version string (max 40 characters);
             * it is not interpreted by the remote side but may be useful for debugging.
             **/
            if(packetEndIndex-PacketStartIndex>100)
                throw new Exception("Too long SSH banner");
            else if(packetEndIndex-PacketStartIndex<8)
                throw new Exception("Too short SSH banner");

            int startIndex=PacketStartIndex;//skip "SSH-"
            if (Utils.ByteConverter.ReadString(parentFrame.Data, ref startIndex, 4, false, false, Utils.ByteConverter.Encoding.Normal) != "SSH-")
                throw new Exception("Data does not start with SSH-");
            string str = Utils.ByteConverter.ReadString(parentFrame.Data, startIndex, packetEndIndex - startIndex);
            while(str.EndsWith("\r") || str.EndsWith("\n"))
                str=str.Substring(0, str.Length-1);
            this.sshVersion=str.Substring(0, str.IndexOf('-'));
            this.sshApplication=str.Substring(str.IndexOf('-')+1);
        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            //throw new Exception("The method or operation is not implemented.");
            yield break;
        }

        #region ISessionPacket Members

        public bool PacketHeaderIsComplete {
            get { return true; }
        }

        public int ParsedBytesCount { get { return base.PacketLength; } }

        #endregion
    }
}
