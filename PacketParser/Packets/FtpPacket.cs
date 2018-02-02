//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Packets {

    //http://tools.ietf.org/html/rfc959
    //This one is only partly implemented (and only a very small part)
    class FtpPacket : AbstractPacket {
        /**
         * 4.1.1.  ACCESS CONTROL COMMANDS
         * USER NAME (USER)
         * PASSWORD (PASS)
         * ACCOUNT (ACCT)
         * CHANGE WORKING DIRECTORY (CWD)
         * CHANGE TO PARENT DIRECTORY (CDUP)
         * STRUCTURE MOUNT (SMNT)
         * REINITIALIZE (REIN)
         * LOGOUT (QUIT)
         * 
         * 4.1.2.  TRANSFER PARAMETER COMMANDS
         * DATA PORT (PORT)
         * PASSIVE (PASV)
         * REPRESENTATION TYPE (TYPE)
         * FILE STRUCTURE (STRU)
         * TRANSFER MODE (MODE)
         * 
         * 4.1.3.  FTP SERVICE COMMANDS
         * RETRIEVE (RETR)
         * STORE (STOR)
         * STORE UNIQUE (STOU)
         * APPEND (with create) (APPE)
         * ALLOCATE (ALLO)
         * RESTART (REST)
         * RENAME FROM (RNFR)
         * RENAME TO (RNTO)
         * ABORT (ABOR)
         * DELETE (DELE)
         * REMOVE DIRECTORY (RMD)
         * MAKE DIRECTORY (MKD)
         * PRINT WORKING DIRECTORY (PWD)
         * LIST (LIST)
         * NAME LIST (NLST)
         * SITE PARAMETERS (SITE)
         * SYSTEM (SYST)
         * STATUS (STAT)
         * HELP (HELP)
         * NOOP (NOOP)
         * */

        /**
         *       5.3.1.  FTP COMMANDS

         The following are the FTP commands:

            USER <SP> <username> <CRLF>
            PASS <SP> <password> <CRLF>
            ACCT <SP> <account-information> <CRLF>
            CWD  <SP> <pathname> <CRLF>
            CDUP <CRLF>
            SMNT <SP> <pathname> <CRLF>
            QUIT <CRLF>
            REIN <CRLF>
            PORT <SP> <host-port> <CRLF>
            PASV <CRLF>
            TYPE <SP> <type-code> <CRLF>
            STRU <SP> <structure-code> <CRLF>
            MODE <SP> <mode-code> <CRLF>
            RETR <SP> <pathname> <CRLF>
            STOR <SP> <pathname> <CRLF>
            STOU <CRLF>
            APPE <SP> <pathname> <CRLF>
            ALLO <SP> <decimal-integer>
                [<SP> R <SP> <decimal-integer>] <CRLF>
            REST <SP> <marker> <CRLF>
            RNFR <SP> <pathname> <CRLF>
            RNTO <SP> <pathname> <CRLF>
            ABOR <CRLF>
            DELE <SP> <pathname> <CRLF>
            RMD  <SP> <pathname> <CRLF>
            MKD  <SP> <pathname> <CRLF>
            PWD  <CRLF>
            LIST [<SP> <pathname>] <CRLF>
            NLST [<SP> <pathname>] <CRLF>
            SITE <SP> <string> <CRLF>
            SYST <CRLF>
            STAT [<SP> <pathname>] <CRLF>
            HELP [<SP> <string>] <CRLF>
            NOOP <CRLF>
         * */

        //private string username, password;
        //private int returnCode;
        private static readonly string[] userCommands = {
            "USER",
            "PASS",
            "ACCT",
            "CWD",
            "CDUP",
            "SMNT",
            "QUIT",
            "REIN",
            "PORT",
            "PASV",
            "TYPE",
            "STRU",
            "MODE",
            "RETR",
            "STOR",
            "STOU",
            "APPE",
            "ALLO", 
            "REST",
            "RNFR",
            "RNTO",
            "ABOR",
            "DELE",
            "RMD",
            "MKD",
            "PWD",
            "LIST",
            "NLST",
            "SITE",
            "SYST",
            "STAT",
            "HELP",
            "NOOP",
            //additional commands outside of the RFC
            "FEAT",
            "SIZE",
            "OPTS"
        };

        private bool clientToServer;

        //request commands
        private string requestCommand, requestArgument;
        //response commands
        private int responseCode;
        private string responseArgument;

        //private System.Net.IPAddress activeIpAddress;
        //private ushort activePort;

        internal bool ClientToServer { get { return clientToServer; } }//could also be named "IsRequest"
        //internal string Username { get { return username; } }
        //internal string Password { get { return password; } }

        internal string RequestCommand{get{return this.requestCommand;}}
        internal string RequestArgument{get{return this.requestArgument;}}
        internal int ResponseCode { get { return this.responseCode; } }
        internal string ResponseArgument{get{return this.responseArgument;}}


        public static bool TryParse(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer, out AbstractPacket result) {
            result = null;
            try {
                if(clientToServer) {
                    //first character should be letter
                    char firstChar = (char)parentFrame.Data[packetStartIndex];
                    if(!Char.IsLetter(firstChar))
                        return false;
                    int index = packetStartIndex;//index will be changed...
                    string command = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);
                    if(command.Contains(" "))
                        command=command.Substring(0, command.IndexOf(' '));
                    if(Array.IndexOf<string>(userCommands, command.ToUpper())==-1)
                        return false;
                }
                else {//server to client
                    //first 3 characters should be numbers
                    if(!Char.IsDigit((char)parentFrame.Data[packetStartIndex]))
                        return false;
                    if(!Char.IsDigit((char)parentFrame.Data[packetStartIndex+1]))
                        return false;
                    if(!Char.IsDigit((char)parentFrame.Data[packetStartIndex+2]))
                        return false;
                    
                    //avoid classifying SMTP as FTP
                    int index = packetStartIndex;
                    if (Utils.ByteConverter.ReadLine(parentFrame.Data, ref index).Contains("ESMTP"))
                        return false;
                }
                result = new FtpPacket(parentFrame, packetStartIndex, packetEndIndex, clientToServer);
                return true;
            }
            catch {
                return false;
            }
        }


        private FtpPacket(Frame parentFrame, int packetStartIndex, int packetEndIndex, bool clientToServer)
            : base(parentFrame, packetStartIndex, packetEndIndex, "FTP") {

            this.clientToServer=clientToServer;
            //this.username=null;
            //this.password=null;
            //this.activeIpAddress=null;
            //this.activePort=0;

            if(clientToServer) {
                int index=PacketStartIndex;
                while(index<=packetEndIndex && index<PacketStartIndex+2000) {//I'll set a limit so that I don't get too much data
                    string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);

                    if(line.Contains(" ")) {
                        this.requestCommand=line.Substring(0, line.IndexOf(' '));
                        if(line.Length>line.IndexOf(' ')+1)
                            this.requestArgument=line.Substring(line.IndexOf(' ')+1);
                        else
                            this.requestArgument="";
                    }
                    else if (line.Length == 3 || line.Length == 4) {
                        this.requestCommand = line.TrimEnd();
                        this.requestArgument = "";
                    }
                    /*
                    if(this.requestCommand=="USER")
                        this.username=this.requestArgument;
                    else if(this.requestCommand=="PASS")
                        this.password=this.requestArgument;*/
                    //else if(this.requestCommand=="PORT") { }

                }
            }
            else {
                //find out the return code
                int index=PacketStartIndex;
                string line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);//I'll only look in the first line
                string first3bytes=line.Substring(0, 3);//will throw exception if line is null (no CR LF in Data)
                if(!Int32.TryParse(first3bytes, out responseCode))
                    responseCode=0;
                else if(line.Length>4)
                    responseArgument=line.Substring(4);
                else
                    responseArgument="";

                if (responseCode > 0 && line.Length > 3) {
                    
                    //check if we have a multi-line command, and if is complete

                    /**
                     * From rfc959:
                     * 
                     * Thus the format for multi-line replies is that the first line
                     * will begin with the exact required reply code, followed
                     * immediately by a Hyphen, "-" (also known as Minus), followed by
                     * text.  The last line will begin with the same code, followed
                     * immediately by Space <SP>, optionally some text, and the Telnet
                     * end-of-line code.
                     * 
                     * For example:
                     * 123-First line
                     * Second line
                     *   234 A line beginning with numbers
                     * 123 The last line
                     * */
                    if (line[3] == '-') {//we have a multi-line reply
                        int responseCodeLastLine = 0;
                        while (responseCodeLastLine != ResponseCode || line.Length < 4 || line[3] != ' ') {
                            line = Utils.ByteConverter.ReadLine(parentFrame.Data, ref index);//one line at a time
                            if (line == null)
                                throw new Exception("Incomplete FTP response");
                            else if (line.Length >= 3) {
                                first3bytes = line.Substring(0, 3);//will throw exception if line is null (no CR LF in Data)
                                if (!Int32.TryParse(first3bytes, out responseCodeLastLine))
                                    responseCodeLastLine = 0;
                            }
                        }
                    }

                }

                base.PacketEndIndex = index - 1;
            }

        }

        public override IEnumerable<AbstractPacket> GetSubPackets(bool includeSelfReference) {
            if(includeSelfReference)
                yield return this;
            yield break;
        }
    }
}
