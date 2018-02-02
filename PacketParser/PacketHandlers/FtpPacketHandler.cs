//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {

    //http://cr.yp.to/ftp.html
    class FtpPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler{

        private class FtpSession{
            private NetworkHost ftpClient, ftpServer;
            private string username, password;

            private PendingFileTransfer pendingFileTransfer;
            private System.Collections.Generic.Dictionary<string, int> fileSizes;
            private string pendingSizeRequestFileName;

            internal NetworkHost ClientHost { get { return this.ftpClient; } }
            internal NetworkHost ServerHost { get { return this.ftpServer; } }
            internal string Username { get { return this.username; } set { this.username=value; } }
            internal string Password { get { return this.password; } set { this.password=value; } }
            internal System.Collections.Generic.Dictionary<string, int> FileSizes { get { return this.fileSizes; } }
            internal string PendingSizeRequestFileName { get { return this.pendingSizeRequestFileName; } set { this.pendingSizeRequestFileName=value; } }

            internal PendingFileTransfer PendingFileTransfer { get { return this.pendingFileTransfer; } set { this.pendingFileTransfer=value; } }

            internal FtpSession(NetworkHost ftpClient, NetworkHost ftpServer) {
                this.ftpClient=ftpClient;
                this.ftpServer=ftpServer;
                this.username=null;
                this.password=null;
                this.fileSizes = new Dictionary<string, int>();
                this.pendingSizeRequestFileName = null;
            }

        }

        private class PendingFileTransfer{
            private NetworkHost dataSessionClient, dataSessionServer;//the TCP client and server of the FTP Data Session (i.e. not the FTP control session to port 21)

            private ushort? dataSessionClientPort;//null if unknown
            private ushort dataSessionServerPort;//port where the TCP server will be listenining for an incoming connection

            bool dataSessionIsPassive;
            private bool? fileDirectionIsDataSessionServerToDataSessionClient;//null if unknown (sorry for the long name!)
            private bool fileTransferSessionEstablished;//true when SYN and SYN+ACK has been sent for the DATA session

            private FtpSession ftpControlSession;
            private string filename;
            private string details;


            internal NetworkHost DataSessionClient { get { return this.dataSessionClient; } }
            internal NetworkHost DataSessionServer { get { return this.dataSessionServer; } }
            internal ushort? DataSessionClientPort {
                get { return this.dataSessionClientPort; }
                set {
                    if(value==null)
                        throw new Exception("Only allwed to assign non-null values");
                    else
                        this.dataSessionClientPort=value;
                }
            }
            internal ushort DataSessionServerPort {
                get { return this.dataSessionServerPort; }
                set { this.dataSessionServerPort=value; }
            }
            internal bool DataSessionIsPassive { get { return this.dataSessionIsPassive; } }
            internal bool? FileDirectionIsDataSessionServerToDataSessionClient {
                get { return this.fileDirectionIsDataSessionServerToDataSessionClient; }
                set {
                    if(value==null)
                        throw new Exception("Only allwed to assign non-null values");
                    else
                        this.fileDirectionIsDataSessionServerToDataSessionClient=value;
                }
            }
            internal bool FileTransferSessionEstablished {
                get { return this.fileTransferSessionEstablished; }
                set {
                    if(value==false)
                        throw new Exception("Established can only be set to true!");
                    else
                        this.fileTransferSessionEstablished=value;
                }
            }
            internal FtpSession FtpControlSession { get { return this.ftpControlSession; } }
            internal string Filename { get { return this.filename; } set { this.filename=value; } }
            internal string Details { get { return this.details; } set { this.details=value; } }

            internal static string GetKey(PendingFileTransfer pendingFileTransfer) {
                return GetKey(pendingFileTransfer.dataSessionClient, pendingFileTransfer.dataSessionClientPort, pendingFileTransfer.dataSessionServer, pendingFileTransfer.dataSessionServerPort);
            }
            internal static string GetKey(NetworkHost dataSessionClient, ushort? dataSessionClientPort, NetworkHost dataSessionServer, ushort? dataSessionServerPort) {
                StringBuilder sb=new StringBuilder();
                sb.Append("Data session client : ");
                sb.Append(dataSessionClient.IPAddress.ToString());
                sb.Append(" TCP/");
                sb.Append(dataSessionClientPort.ToString());
                sb.Append("\nData session server : ");
                sb.Append(dataSessionServer.IPAddress.ToString());
                sb.Append(" TCP/");
                sb.Append(dataSessionServerPort.ToString());
                return sb.ToString();
            }

            internal PendingFileTransfer(NetworkHost dataSessionClient, ushort? dataSessionClientPort, NetworkHost dataSessionServer, ushort dataSessionServerPort, bool dataSessionIsPassive, FtpSession ftpControlSession){
                this.dataSessionClient=dataSessionClient;
                this.dataSessionClientPort=dataSessionClientPort;
                this.dataSessionServer=dataSessionServer;
                this.dataSessionServerPort=dataSessionServerPort;

                this.dataSessionIsPassive=dataSessionIsPassive;
                this.fileDirectionIsDataSessionServerToDataSessionClient=null;
                this.fileTransferSessionEstablished=false;

                this.ftpControlSession=ftpControlSession;
                this.filename=null;
                this.details="";
            }

            public override string ToString() {
                return GetKey(this)+"\nFilename: "+this.filename+"\nDetials: "+this.details;
            }

            internal string GetKey() {
                return GetKey(this);
            }

            public FiveTuple GetFiveTuple() {
                return new FiveTuple(this.dataSessionClient, this.dataSessionClientPort.Value, this.dataSessionServer, this.dataSessionServerPort, FiveTuple.TransportProtocol.TCP);
            }
        }

        //FTP control sessions (to TCP/21)
        private PopularityList<NetworkTcpSession, FtpSession> ftpSessionList;

        //FTP data sessions (from TCP/20 if active)
        private PopularityList<string, PendingFileTransfer> pendingFileTransferList;

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.FtpControl; }
        }

        //public FtpPacketHandler(NetworkMinerForm parentForm, FileTransfer.FileStreamAssemblerPool fileStreamAssemblerPool, SortedList<NetworkCredential, NetworkCredential> credentialList): base(parentForm) {
        public FtpPacketHandler(PacketHandler mainPacketHandler) : base(mainPacketHandler){
            this.ftpSessionList=new PopularityList<NetworkTcpSession, FtpSession>(100);//max 100 simultaneous FTP control sessions
            this.pendingFileTransferList=new PopularityList<string, PendingFileTransfer>(20);
        }

        


        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            /*
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }*/

            Packets.TcpPacket tcpPacket=null;
            Packets.FtpPacket ftpPacket=null;

            foreach(Packets.AbstractPacket p in packetList) {
                if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
                else if(p.GetType()==typeof(Packets.FtpPacket))
                    ftpPacket=(Packets.FtpPacket)p;
            }
            
            FtpSession ftpSession=null;//we can only have one FtpSession per packet...
            //bool returnValue=false;
            int parsedBytes = 0;

            
            if(tcpSession.SynPacketReceived && tcpSession.SynAckPacketReceived) {
                //start by checking if this is an incoming file transfer through FTP
                if(!tcpSession.SessionEstablished){
                    //we now have an upcoming session

                    //see if it matches the pending FTP data sessions
                    if(this.pendingFileTransferList.ContainsKey(PendingFileTransfer.GetKey(tcpSession.ClientHost, tcpSession.ClientTcpPort, tcpSession.ServerHost, tcpSession.ServerTcpPort))){
                        PendingFileTransfer pending=this.pendingFileTransferList[PendingFileTransfer.GetKey(tcpSession.ClientHost, tcpSession.ClientTcpPort, tcpSession.ServerHost, tcpSession.ServerTcpPort)];
                        pending.FileTransferSessionEstablished=true;
                        ftpSession=pending.FtpControlSession;
                        //returnValue=true;//we managed to get some data out of this!
                        parsedBytes = tcpPacket.PayloadDataLength;
                    }
                    //see if the client port was unknown
                    else if(this.pendingFileTransferList.ContainsKey(PendingFileTransfer.GetKey(tcpSession.ClientHost, null, tcpSession.ServerHost, tcpSession.ServerTcpPort))){
                        PendingFileTransfer pending=this.pendingFileTransferList[PendingFileTransfer.GetKey(tcpSession.ClientHost, null, tcpSession.ServerHost, tcpSession.ServerTcpPort)];
                        this.pendingFileTransferList.Remove(pending.GetKey());
                        pending.DataSessionClientPort=tcpSession.ClientTcpPort;//the Key will now be changed!
                        pending.FileTransferSessionEstablished=true;
                        this.pendingFileTransferList.Add(pending.GetKey(), pending);
                        ftpSession=pending.FtpControlSession;
                        //returnValue=true;
                        parsedBytes = tcpPacket.PayloadDataLength;
                    }

                }//end check for new FTP DATA sessions
                else if(tcpPacket!=null && tcpPacket.FlagBits.Fin) {
                    //check if there is an FTP data session being closed
                    if(this.MainPacketHandler.FileStreamAssemblerList.ContainsAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer, true, PacketParser.FileTransfer.FileStreamTypes.FTP)) {
                        PacketParser.FileTransfer.FileStreamAssembler assembler=this.MainPacketHandler.FileStreamAssemblerList.GetAssembler(tcpSession.Flow.FiveTuple, transferIsClientToServer);
                        if(assembler.FileContentLength==-1 && assembler.FileSegmentRemainingBytes==-1)
                            //TODO: see if all data has been received or if the FIN arrived before the final data packet
                            assembler.FinishAssembling();
                    }
                }
            }

            if(ftpPacket!=null && tcpPacket!=null) {
                //returnValue=true;
                parsedBytes = ftpPacket.PacketLength;

                if(ftpSessionList.ContainsKey(tcpSession))
                    ftpSession=ftpSessionList[tcpSession];
                else {
                    ftpSession=new FtpSession(tcpSession.ClientHost, tcpSession.ServerHost);
                    this.ftpSessionList.Add(tcpSession, ftpSession);
                }
                /*
                NetworkHost sourceHost, destinationHost;
                if (transferIsClientToServer) {
                    sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                    destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
                }
                else {
                    sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                    destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
                }
                */
                if (ftpPacket.ClientToServer) {
                    if(ftpPacket.RequestCommand!=null) {
                        if(ftpPacket.RequestArgument!=null) {
                            System.Collections.Specialized.NameValueCollection tmpCol=new System.Collections.Specialized.NameValueCollection();
                            tmpCol.Add(ftpPacket.RequestCommand, ftpPacket.RequestArgument);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(ftpPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, tmpCol, ftpPacket.ParentFrame.Timestamp, "FTP Request"));
                        }
                        if(ftpPacket.RequestCommand.ToUpper()=="USER") {//username
                            ftpSession.Username=ftpPacket.RequestArgument;

                        }
                        else if(ftpPacket.RequestCommand.ToUpper()=="PASS") {//password
                            ftpSession.Password=ftpPacket.RequestArgument;
                            if(ftpSession.Username!=null && ftpSession.Password!=null) {
                                base.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, ftpPacket.PacketTypeDescription, ftpSession.Username, ftpSession.Password, ftpPacket.ParentFrame.Timestamp));
                            }

                        }
                        else if(ftpPacket.RequestCommand.ToUpper()=="PORT") {

                            ushort clientListeningOnPort;
                            if(TryGetPort(ftpPacket.RequestArgument, out clientListeningOnPort)) {
                                //ftpSession.ActiveMode=true;
                                //ftpSession.ClientDataListenerTcpPort=this.GetPort(ftpPacket.RequestArgument);

                                //ftpSession.PendingFileTransfer=new PendingFileTransfer(ftpSession.ServerHost, (ushort)20, ftpSession.ClientHost, clientListeningOnPort, false, ftpSession);
                                ftpSession.PendingFileTransfer=new PendingFileTransfer(ftpSession.ServerHost, null, ftpSession.ClientHost, clientListeningOnPort, false, ftpSession);
                                if(this.pendingFileTransferList.ContainsKey(ftpSession.PendingFileTransfer.GetKey()))
                                    this.pendingFileTransferList.Remove(ftpSession.PendingFileTransfer.GetKey());
                                this.pendingFileTransferList.Add(ftpSession.PendingFileTransfer.GetKey(), ftpSession.PendingFileTransfer);

                            }

                        }
                        else if(ftpPacket.RequestCommand.ToUpper()=="STOR") {//file upload (client -> server)

                            //set filename and file direction
                            if(ftpSession.PendingFileTransfer!=null) {
                                ftpSession.PendingFileTransfer.Filename=ftpPacket.RequestArgument;
                                ftpSession.PendingFileTransfer.FileDirectionIsDataSessionServerToDataSessionClient=!ftpSession.PendingFileTransfer.DataSessionIsPassive;
                                ftpSession.PendingFileTransfer.Details=ftpPacket.RequestCommand+" "+ftpPacket.RequestArgument;
                            }
                            else {
                                //ftpPacket.ParentFrame.Errors.Add(new Frame.Error(ftpPacket.ParentFrame, ftpPacket.PacketStartIndex, ftpPacket.PacketEndIndex, "STOR command without a pending ftp data session"));
                                this.MainPacketHandler.OnAnomalyDetected("STOR command without a pending ftp data session. Frame: "+ftpPacket.ParentFrame.ToString(), ftpPacket.ParentFrame.Timestamp);
                                //System.Diagnostics.Debugger.Break();//this should not occur!
                            }


                        }
                        else if(ftpPacket.RequestCommand.ToUpper()=="RETR") {//file download (server -> client)
                            if(ftpSession.PendingFileTransfer!=null) {
                                ftpSession.PendingFileTransfer.Filename=ftpPacket.RequestArgument;
                                ftpSession.PendingFileTransfer.FileDirectionIsDataSessionServerToDataSessionClient=ftpSession.PendingFileTransfer.DataSessionIsPassive;
                                ftpSession.PendingFileTransfer.Details=ftpPacket.RequestCommand+" "+ftpPacket.RequestArgument;
                            }
                            else {
                                //System.Diagnostics.Debugger.Break();//this should not iccur
                                //ftpPacket.ParentFrame.Errors.Add(new Frame.Error(ftpPacket.ParentFrame, ftpPacket.PacketStartIndex, ftpPacket.PacketEndIndex, "RETR command without a pending ftp data session"));
                                this.MainPacketHandler.OnAnomalyDetected("RETR command without a pending ftp data session. Frame: "+ftpPacket.ParentFrame.ToString(), ftpPacket.ParentFrame.Timestamp);
                            }

                        }
                        else if (ftpPacket.RequestCommand.ToUpper() == "SIZE") {
                            ftpSession.PendingSizeRequestFileName = ftpPacket.RequestArgument;
                        }
                        
                    }
                }
                else {//server to client packet
                    if(ftpPacket.ResponseCode!=0 && ftpPacket.ResponseArgument!=null) {
                        System.Collections.Specialized.NameValueCollection tmpCol=new System.Collections.Specialized.NameValueCollection();
                        tmpCol.Add(ftpPacket.ResponseCode.ToString(), ftpPacket.ResponseArgument);
                        MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(ftpPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, tmpCol, ftpPacket.ParentFrame.Timestamp, "FTP Response"));

                        //look for an FTP banner
                        if(ftpPacket.ResponseCode==220 && ftpPacket.ResponseArgument.ToLower().Contains("ftp"))
                            tcpSession.Flow.FiveTuple.ServerHost.AddFtpServerBanner(ftpPacket.ResponseArgument, tcpPacket.SourcePort);
                    }
                    if (ftpPacket.ResponseCode == 213 && ftpSession.PendingSizeRequestFileName!=null) {//File size response
                        int fileSize;
                        if (Int32.TryParse(ftpPacket.ResponseArgument, out fileSize))
                            ftpSession.FileSizes[ftpSession.PendingSizeRequestFileName] = fileSize;
                            //ftpSession.FileSizes.Add(ftpSession.PendingSizeRequestFileName, fileSize);
                        ftpSession.PendingSizeRequestFileName = null;
                    }
                    if(ftpPacket.ResponseCode==226) {//File receive OK
                        //close file stream assembler?
                    }
                    else if (ftpPacket.ResponseCode == 227) {//Entering Passive Mode - Response to client "PASV" command
                        
                        //From: http://cr.yp.to/ftp/retr.html
                        //Many servers put different strings before h1 and after p2.
                        //I recommend that clients use the following strategy to parse the
                        //response line: look for the first digit after the initial space;
                        //look for the fourth comma after that digit; read two (possibly negative)
                        //integers, separated by a comma; the TCP port number is p1*256+p2,
                        //where p1 is the first integer modulo 256 and p2 is the second integer
                        //modulo 256. 

                        //it is probably simpler to do this with RegEx, but this is simple enough so I wont bother with RegEx for now...
                        char[] digits={'0','1','2','3','4','5','6','7','8','9'};
                        string ipAndPort=ftpPacket.ResponseArgument.Substring(ftpPacket.ResponseArgument.IndexOfAny(digits));
                        //string ipAndPort=ftpPacket.ResponseArgument.Substring(ftpPacket.ResponseArgument.IndexOf('(')+1);
                        ipAndPort=ipAndPort.Substring(0, ipAndPort.LastIndexOfAny(digits)+1);
                        //ipAndPort=ipAndPort.Substring(0, ipAndPort.IndexOf(')'));
                        ushort serverListeningOnPort;
                        if(this.TryGetPort(ipAndPort, out serverListeningOnPort)) {
                            ftpSession.PendingFileTransfer=new PendingFileTransfer(ftpSession.ClientHost, null, ftpSession.ServerHost, serverListeningOnPort, true, ftpSession);
                            if(this.pendingFileTransferList.ContainsKey(ftpSession.PendingFileTransfer.GetKey()))
                                this.pendingFileTransferList.Remove(ftpSession.PendingFileTransfer.GetKey());
                            this.pendingFileTransferList.Add(ftpSession.PendingFileTransfer.GetKey(), ftpSession.PendingFileTransfer);
                        }
                    }
                    else if(ftpPacket.ResponseCode==230) {//Login successful
                        //ftpSession.=ftpPacket.RequestArgument;
                        if(ftpSession.Username!=null && ftpSession.Password!=null) {
                            base.MainPacketHandler.AddCredential(new NetworkCredential(tcpSession.ClientHost, tcpSession.ServerHost, ftpPacket.PacketTypeDescription, ftpSession.Username, ftpSession.Password, true, ftpPacket.ParentFrame.Timestamp));
                        }

                    }
                    else if (ftpPacket.ResponseCode == 234) {//server response to an 'AUTH TLS' command rfc4217 and rfc2228
                       /**
                        * If the server is willing to accept the named security mechanism,
                        * and does not require any security data, it must respond with reply
                        * code 234.
                        **/
                        //Unfortunately we haven't stored the request, so we can't know if the client was asking for TLS or some other security measure
                        if(ftpPacket.ResponseArgument.Contains("TLS") || ftpPacket.ResponseArgument.Contains("SSL")) {
                            tcpSession.ProtocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Ssl, false);
                        }

                    }
                }//end server to client

            }
            if(ftpSession!=null && ftpSession.PendingFileTransfer!=null){
                //I guess returnValue is already set to true by now, but I'll do it again just to be sure...
                if (parsedBytes == 0)
                    parsedBytes = tcpPacket.PayloadDataLength;
                //returnValue=true;
                PendingFileTransfer pending=ftpSession.PendingFileTransfer;
                //see if the pending file transfer could be transformed into a real file stream assembler
                if(pending.FileTransferSessionEstablished && pending.FileDirectionIsDataSessionServerToDataSessionClient!=null && pending.DataSessionClientPort!=null){
                    //Server->Client ?

                    FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation fileAssemblyLocation;
                    if ((ftpSession.ServerHost == pending.DataSessionServer) == pending.FileDirectionIsDataSessionServerToDataSessionClient.Value)
                        fileAssemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source;
                    else
                        fileAssemblyLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination;
                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, pending.GetFiveTuple(), !pending.FileDirectionIsDataSessionServerToDataSessionClient.Value, FileTransfer.FileStreamTypes.FTP, pending.Filename, "/", pending.Details, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, fileAssemblyLocation);

                    string fileCompletePath = "";
                    if (assembler.Filename != null && assembler.FileLocation != null)
                        fileCompletePath = assembler.FileLocation + "/" + assembler.Filename;
                    if (ftpSession.FileSizes.ContainsKey(fileCompletePath)) {
                        assembler.FileContentLength = ftpSession.FileSizes[fileCompletePath];
                        assembler.FileSegmentRemainingBytes = ftpSession.FileSizes[fileCompletePath];
                    }
                    else {
                        //-1 is set instead of null if Content-Length is not defined
                        assembler.FileContentLength = -1;
                        assembler.FileSegmentRemainingBytes = -1;
                    }
                    if(assembler.TryActivate())
                        MainPacketHandler.FileStreamAssemblerList.Add(assembler);
                    //assembler.Activate();
                    //the file transfer is no longer pending since the assembler is started!
                    pendingFileTransferList.Remove(pending.GetKey());
                    ftpSession.PendingFileTransfer=null;
                    
                }

            }
            return parsedBytes;

        }

        public void Reset() {
            this.ftpSessionList.Clear();
            this.pendingFileTransferList.Clear();
            //this.pendingFtpDataSessionList.Clear();
        }
        #endregion//end of ITcpPayloadPacketHandler interface methods


        private bool TryGetPort(string commaSeparatedIpAndPortString, out ushort portNumber) {
            portNumber=0;//default value
            try {
                char[] separators={ ',', ' ', '\r', '\n' };
                string[] data=commaSeparatedIpAndPortString.Split(separators);
                if(data.Length<6)
                    return false;
                ushort port=0;
                for(int i=4; i<6; i++) {
                    byte b;
                    if(Byte.TryParse(data[i], out b))
                        port=(ushort)((port<<8)+b);
                    else
                        return false;
                }
                portNumber=port;
                return true;
            }
            catch {
                return false;
            }
        }



    }
}
