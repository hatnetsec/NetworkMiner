//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class SmbCommandPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        //private System.Collections.Generic.SortedList<string, FileTransfer.FileStreamAssembler> smbAssemblers;
        private PopularityList<string, SmbSession> smbSessionPopularityList;

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.NetBiosSessionService; }
        }

        public SmbCommandPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {

            //this.smbAssemblers=new SortedList<string, NetworkMiner.FileTransfer.FileStreamAssembler>();
            this.smbSessionPopularityList=new PopularityList<string, SmbSession>(100);
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
            bool successfulExtraction =false;


            

            Packets.TcpPacket tcpPacket=null;

            List<Packets.AbstractPacket> packets = new List<Packets.AbstractPacket>(packetList);
            foreach (Packets.AbstractPacket p in packets) {
                if (p.GetType() == typeof(Packets.TcpPacket))
                    tcpPacket = (Packets.TcpPacket)p;
            }
            //there can be multiple SMB2 commands in the same NetBiosSessionServicePacket
            foreach (Packets.AbstractPacket p in packets) {
                if (p.GetType().IsSubclassOf(typeof(Packets.SmbPacket.AbstractSmbCommand)))
                    ExtractSmbData(tcpSession, transferIsClientToServer, tcpPacket, (Packets.SmbPacket.AbstractSmbCommand)p, base.MainPacketHandler);

            }
            return 0;//NetBiosSessionServicePacketHandler will return the # parsed bytes anyway.
        }

        public void Reset() {
            this.smbSessionPopularityList.Clear();
        }

        #endregion

        private void ExtractSmbData(NetworkTcpSession tcpSession, bool transferIsClientToServer, Packets.TcpPacket tcpPacket, Packets.SmbPacket.AbstractSmbCommand smbCommandPacket, PacketHandler mainPacketHandler) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = tcpSession.Flow.FiveTuple.ClientHost;
                destinationHost = tcpSession.Flow.FiveTuple.ServerHost;
            }
            else {
                sourceHost = tcpSession.Flow.FiveTuple.ServerHost;
                destinationHost = tcpSession.Flow.FiveTuple.ClientHost;
            }
            string smbSessionId;
            if(smbCommandPacket.ParentCifsPacket.FlagsResponse)
                smbSessionId=SmbSession.GetSmbSessionId(sourceHost.IPAddress, tcpPacket.SourcePort, destinationHost.IPAddress, tcpPacket.DestinationPort);
            else
                smbSessionId=SmbSession.GetSmbSessionId(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);


            if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.NegotiateProtocolRequest)) {
                Packets.SmbPacket.NegotiateProtocolRequest request = (Packets.SmbPacket.NegotiateProtocolRequest)smbCommandPacket;
                sourceHost.AcceptedSmbDialectsList = request.DialectList;
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.NegotiateProtocolResponse)) {
                Packets.SmbPacket.NegotiateProtocolResponse reply = (Packets.SmbPacket.NegotiateProtocolResponse)smbCommandPacket;
                if (destinationHost.AcceptedSmbDialectsList != null && destinationHost.AcceptedSmbDialectsList.Count > reply.DialectIndex)
                    sourceHost.PreferredSmbDialect = destinationHost.AcceptedSmbDialectsList[reply.DialectIndex];
                //sourceHost.ExtraDetailsList.Add("Preferred SMB dialect", destinationHost.AcceptedSmbDialectsList[reply.DialectIndex]);
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.TreeConnectAndXRequest)) {
                Packets.SmbPacket.TreeConnectAndXRequest request = (Packets.SmbPacket.TreeConnectAndXRequest)smbCommandPacket;
                if (request.ShareName != null && request.ShareName.Length > 0) {
                    destinationHost.AddNumberedExtraDetail("SMB File Share", request.ShareName);

                    System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                    parameters.Add("SMB Tree Connect AndX Request " + request.ParentCifsPacket.MultiplexId.ToString(), request.ShareName);
                    mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(smbCommandPacket.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, smbCommandPacket.ParentFrame.Timestamp, "SMB Tree Connect AndX Request"));

                    SmbSession smbSession;
                    if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                        smbSession = this.smbSessionPopularityList[smbSessionId];
                    }
                    else {
                        smbSession = new SmbSession(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);
                        this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                    }
                    smbSession.AddTreeConnectAndXRequestPath(smbCommandPacket.ParentCifsPacket.UserId, smbCommandPacket.ParentCifsPacket.MultiplexId, request.ShareName);
                }
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.TreeConnectAndXResponse)) {
                SmbSession smbSession;
                if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                    smbSession = this.smbSessionPopularityList[smbSessionId];
                }
                else {
                    smbSession = new SmbSession(sourceHost.IPAddress, tcpPacket.SourcePort, destinationHost.IPAddress, tcpPacket.DestinationPort);
                    this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                }
                smbSession.StoreTreeConnectAndXRequestPathForTree(smbCommandPacket.ParentCifsPacket.UserId, smbCommandPacket.ParentCifsPacket.MultiplexId, smbCommandPacket.ParentCifsPacket.TreeId);
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.SetupAndXRequest)) {
                Packets.SmbPacket.SetupAndXRequest request = (Packets.SmbPacket.SetupAndXRequest)smbCommandPacket;
                if (request.NativeLanManager != null && request.NativeLanManager.Length > 0) {
                    if (sourceHost.ExtraDetailsList.ContainsKey("SMB Native LAN Manager"))
                        sourceHost.ExtraDetailsList["SMB Native LAN Manager"] = request.NativeLanManager;
                    else
                        sourceHost.ExtraDetailsList.Add("SMB Native LAN Manager", request.NativeLanManager);
                }

                if (request.NativeOs != null && request.NativeOs.Length > 0) {
                    if (sourceHost.ExtraDetailsList.ContainsKey("SMB Native OS"))
                        sourceHost.ExtraDetailsList["SMB Native OS"] = request.NativeOs;
                    else
                        sourceHost.ExtraDetailsList.Add("SMB Native OS", request.NativeOs);
                }

                if (request.PrimaryDomain != null && request.PrimaryDomain.Length > 0) {
                    sourceHost.AddDomainName(request.PrimaryDomain);
                }
                if (request.AccountName != null && request.AccountName.Length > 0) {
                    NetworkCredential nCredential = new NetworkCredential(sourceHost, destinationHost, smbCommandPacket.PacketTypeDescription, request.AccountName, request.ParentFrame.Timestamp);
                    if (request.AccountPassword != null && request.AccountPassword.Length > 0)
                        nCredential.Password = request.AccountPassword;
                    mainPacketHandler.AddCredential(nCredential);
                }
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.SetupAndXResponse)) {
                Packets.SmbPacket.SetupAndXResponse response = (Packets.SmbPacket.SetupAndXResponse)smbCommandPacket;
                if (response.NativeLanManager != null && response.NativeLanManager.Length > 0) {
                    if (sourceHost.ExtraDetailsList.ContainsKey("SMB Native LAN Manager"))
                        sourceHost.ExtraDetailsList["SMB Native LAN Manager"] = response.NativeLanManager;
                    else
                        sourceHost.ExtraDetailsList.Add("SMB Native LAN Manager", response.NativeLanManager);
                }

                if (response.NativeOs != null && response.NativeOs.Length > 0) {
                    if (sourceHost.ExtraDetailsList.ContainsKey("SMB Native OS"))
                        sourceHost.ExtraDetailsList["SMB Native OS"] = response.NativeOs;
                    else
                        sourceHost.ExtraDetailsList.Add("SMB Native OS", response.NativeOs);
                }
            }
            else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.NTCreateAndXRequest)) {
                Packets.SmbPacket.NTCreateAndXRequest request = (Packets.SmbPacket.NTCreateAndXRequest)smbCommandPacket;
                string filename, filePath;

                if (request.Filename.EndsWith("\0"))
                    filename = request.Filename.Remove(request.Filename.Length - 1);
                else
                    filename = request.Filename;

                //print raw filename on parameters tab
                System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                parameters.Add("SMB NT Create AndX Request " + request.ParentCifsPacket.MultiplexId.ToString(), filename);
                base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(request.ParentFrame.FrameNumber, tcpSession.Flow.FiveTuple, transferIsClientToServer, parameters, request.ParentFrame.Timestamp, "SMB NTCreateAndXRequest"));

                SmbSession smbSession;
                if (this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                    smbSession = this.smbSessionPopularityList[smbSessionId];
                }
                else {
                    smbSession = new SmbSession(destinationHost.IPAddress, tcpPacket.DestinationPort, sourceHost.IPAddress, tcpPacket.SourcePort);
                    this.smbSessionPopularityList.Add(smbSessionId, smbSession);
                }

                string treePath = smbSession.GetPathForTree(smbCommandPacket.ParentCifsPacket.TreeId);
                if (treePath == null)
                    filePath = "";
                else
                    filePath = treePath + System.IO.Path.DirectorySeparatorChar;

                if (System.IO.Path.DirectorySeparatorChar != '\\' && filename.Contains("\\"))
                    filename.Replace('\\', System.IO.Path.DirectorySeparatorChar);

                if (filename.Contains(System.IO.Path.DirectorySeparatorChar.ToString())) {
                    filePath += filename.Substring(0, filename.LastIndexOf(System.IO.Path.DirectorySeparatorChar.ToString()));
                    filename = filename.Substring(filename.LastIndexOf(System.IO.Path.DirectorySeparatorChar.ToString()) + 1);
                }
                else
                    filePath += System.IO.Path.DirectorySeparatorChar.ToString();

                try {

                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, tcpSession.Flow.FiveTuple, !transferIsClientToServer, FileTransfer.FileStreamTypes.SMB, filename, filePath, filePath + filename, smbCommandPacket.ParentFrame.FrameNumber, smbCommandPacket.ParentFrame.Timestamp);
                    smbSession.AddFileStreamAssembler(assembler, request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId);

                }
                catch (Exception e) {
                    MainPacketHandler.OnAnomalyDetected("Error creating assembler for SMB file transfer: " + e.Message);

                }
            }
            //else if(!smbCommandPacket.ParentCifsPacket.FlagsResponse && mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, true)) {
            else if (!smbCommandPacket.ParentCifsPacket.FlagsResponse && this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                //Request
                if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.CloseRequest) && smbSessionPopularityList.ContainsKey(smbSessionId)) {

                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    Packets.SmbPacket.CloseRequest closeRequest = (Packets.SmbPacket.CloseRequest)smbCommandPacket;
                    ushort fileId = closeRequest.FileId;
                    //FileTransfer.FileStreamAssembler assemblerToClose;
                    if (smbSession.ContainsFileId(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId)) {
                        FileTransfer.FileStreamAssembler assemblerToClose = smbSession.GetFileStreamAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId);
                        if (assemblerToClose != null && assemblerToClose.AssembledByteCount >= assemblerToClose.FileContentLength)
                            assemblerToClose.FinishAssembling();
                        FileTransfer.FileSegmentAssembler segmentAssemblerToClose = smbSession.GetFileSegmentAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId);
                        if (segmentAssemblerToClose != null)
                            segmentAssemblerToClose.Close();

                        smbSession.RemoveFileStreamAssembler(closeRequest.ParentCifsPacket.TreeId, closeRequest.ParentCifsPacket.MultiplexId, closeRequest.ParentCifsPacket.ProcessId, fileId, false);

                        //TODO: remove the following line (added for debugging purpose 2011-04-25)
                        //assemblerToClose.FinishAssembling();

                        if (mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(assemblerToClose))
                            mainPacketHandler.FileStreamAssemblerList.Remove(assemblerToClose, true);
                        else
                            assemblerToClose.Clear();
                    }




                }
                else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.ReadAndXRequest) && smbSessionPopularityList.ContainsKey(smbSessionId)) {
                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    //Packets.CifsPacket.ReadAndXRequest request=this.smbSessionPopularityList[smbSessionId];
                    Packets.SmbPacket.ReadAndXRequest readRequest = (Packets.SmbPacket.ReadAndXRequest)smbCommandPacket;
                    ushort fileId = readRequest.FileId;
                    smbSession.Touch(readRequest.ParentCifsPacket.TreeId, readRequest.ParentCifsPacket.MultiplexId, readRequest.ParentCifsPacket.ProcessId, fileId);
                }
                else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.WriteAndXRequest)) {
                    SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];
                    Packets.SmbPacket.WriteAndXRequest request = (Packets.SmbPacket.WriteAndXRequest)smbCommandPacket;
                    FileTransfer.FileSegmentAssembler segmentAssembler = smbSession.GetFileSegmentAssembler(request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId, request.FileId);
                    if (segmentAssembler == null) {
                        string outputDir = System.IO.Path.GetDirectoryName(mainPacketHandler.OutputDirectory);
                        FileTransfer.FileStreamAssembler tmpAssembler = smbSession.GetFileStreamAssembler(request.ParentCifsPacket.TreeId, request.ParentCifsPacket.MultiplexId, request.ParentCifsPacket.ProcessId, request.FileId);
                        if (tmpAssembler != null) {
                            string filePath = tmpAssembler.FileLocation;
                            if (filePath.Length == 0 || filePath.EndsWith("/"))
                                filePath += tmpAssembler.Filename;
                            else
                                filePath += "/" + tmpAssembler.Filename;

                            segmentAssembler = new FileTransfer.FileSegmentAssembler(outputDir, tcpSession, false, filePath, tcpSession.ToString() + "SMB" + request.FileId.ToString(), mainPacketHandler.FileStreamAssemblerList, null, FileTransfer.FileStreamTypes.SMB, "SMB Write " + tmpAssembler.Details, null);
                            smbSession.AddFileSegmentAssembler(segmentAssembler, request.FileId);
                        }
                    }

                    if (segmentAssembler != null) {
                        segmentAssembler.AddData(request.WriteOffset, request.GetFileData(), request.ParentFrame);
                    }

                }


            }
            else if (smbCommandPacket.ParentCifsPacket.FlagsResponse && this.smbSessionPopularityList.ContainsKey(smbSessionId)) {
                //Response
                SmbSession smbSession = this.smbSessionPopularityList[smbSessionId];

                //FileTransfer.FileStreamAssembler assembler=mainPacketHandler.FileStreamAssemblerList.GetAssembler(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, true);

                if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.NTCreateAndXResponse)) {
                    Packets.SmbPacket.NTCreateAndXResponse response = (Packets.SmbPacket.NTCreateAndXResponse)smbCommandPacket;
                    ushort fileId = response.FileId;
                    int fileLength = (int)response.EndOfFile;//yes, I know I will not be able to store big files now... but an int as length is really enough!

                    //tag the requested file with the fileId
                    FileTransfer.FileStreamAssembler assembler = smbSession.GetLastReferencedFileStreamAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);
                    smbSession.RemoveLastReferencedAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);



                    if (assembler != null) {
                        //Add file ID as extended ID in order to differentiate between parallell file transfers on disk cache
                        assembler.ExtendedFileId = "Id" + fileId.ToString("X4"); //2011-04-18

                        smbSession.AddFileStreamAssembler(assembler, response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId, response.FileId);

                        assembler.FileContentLength = fileLength;
                    }


                }
                else if (smbCommandPacket.GetType() == typeof(Packets.SmbPacket.ReadAndXResponse)) {
                    Packets.SmbPacket.ReadAndXResponse response = (Packets.SmbPacket.ReadAndXResponse)smbCommandPacket;
                    //move the assembler to the real FileStreamAssemblerList!
                    FileTransfer.FileStreamAssembler assembler = smbSession.GetLastReferencedFileStreamAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);
                    if (assembler == null) {
                        base.MainPacketHandler.OnAnomalyDetected("Unable to find assembler for frame " + smbCommandPacket.ParentFrame.FrameNumber + " : " + smbCommandPacket.ToString());
                    }
                    else if (assembler != null) {
                        /* Removed 2011-04-25
                        if(!mainPacketHandler.FileStreamAssemblerList.ContainsAssembler(assembler))
                            mainPacketHandler.FileStreamAssemblerList.Add(assembler);
                         * */

                        assembler.FileSegmentRemainingBytes += response.DataLength;//setting this one so that it can receive more bytes
                        if (!assembler.IsActive) {
                            System.Diagnostics.Debug.Assert(assembler.ExtendedFileId != null && assembler.ExtendedFileId != "", "No FileID set for SMB file transfer!");

                            if (!assembler.TryActivate()) {
                                if (!response.ParentCifsPacket.ParentFrame.QuickParse)
                                    response.ParentCifsPacket.ParentFrame.Errors.Add(new Frame.Error(response.ParentCifsPacket.ParentFrame, response.PacketStartIndex, response.PacketEndIndex, "Unable to activate file stream assembler for " + assembler.FileLocation + "/" + assembler.Filename));
                            }
                            else if (assembler.IsActive)
                                assembler.AddData(response.GetFileData(), tcpPacket.SequenceNumber);

                        }
                        /* Removed 2011-04-25
                        if(!assembler.IsActive) {//see if the file is fully assembled or if something else went wrong...
                            smbSession.RemoveLastReferencedAssembler(response.ParentCifsPacket.TreeId, response.ParentCifsPacket.MultiplexId, response.ParentCifsPacket.ProcessId);
                        }
                         * */
                    }
                }

            }
        }


        internal class SmbSession {
            private System.Net.IPAddress serverIP, clientIP;
            private ushort serverTcpPort, clientTcpPort;
            
            //treeId|multiplexId
            private System.Collections.Generic.SortedList<uint, ushort> lastReferencedFileIdPerTreeMux;

            //processId|multiplexId (like Wireshark do in smb_saved_info_equal_unmatched of packet-smb.c)
            private System.Collections.Generic.SortedList<uint, ushort> lastReferencedFileIdPerPidMux;
            //private ushort lastReferencedFileId;

            //private System.Collections.Generic.SortedList<ushort, FileTransfer.FileStreamAssembler> fileIdAssemblerList;
            private PopularityList<ushort, FileTransfer.FileStreamAssembler> fileIdAssemblerList;
            private PopularityList<ushort, FileTransfer.FileSegmentAssembler> fileIdSegmentAssemblerList;

            private PopularityList<int, string> lastTreeConnectAndXRequestPathPerUserMux;
            private PopularityList<ushort, string> treePathList;

            //internal PopularityList<ushort, FileTransfer.FileStreamAssembler> FileIdAssemblerList { get { return this.fileIdAssemblerList; } }

            internal static string GetSmbSessionId(System.Net.IPAddress serverIP, ushort serverTcpPort, System.Net.IPAddress clientIP, ushort clientTcpPort) {
                return serverIP.ToString()+":"+serverTcpPort.ToString("X4")+"-"+clientIP.ToString()+":"+clientTcpPort.ToString("X4");
            }

            internal SmbSession(System.Net.IPAddress serverIP, ushort serverTcpPort, System.Net.IPAddress clientIP, ushort clientTcpPort) {
                this.serverIP=serverIP;
                this.serverTcpPort=serverTcpPort;
                this.clientIP=clientIP;
                this.clientTcpPort=clientTcpPort;

                this.lastReferencedFileIdPerTreeMux=new SortedList<uint, ushort>();
                this.lastReferencedFileIdPerPidMux=new SortedList<uint, ushort>();


                this.fileIdAssemblerList=new PopularityList<ushort, FileTransfer.FileStreamAssembler>(100);
                this.fileIdAssemblerList.PopularityLost += FileIdAssemblerList_PopularityLost;
                this.fileIdSegmentAssemblerList = new PopularityList<ushort, FileTransfer.FileSegmentAssembler>(100);
                this.fileIdSegmentAssemblerList.PopularityLost += FileIdSegmentAssemblerList_PopularityLost;

                this.lastTreeConnectAndXRequestPathPerUserMux = new PopularityList<int, string>(100);
                this.treePathList = new PopularityList<ushort, string>(100);
            }

            private void FileIdAssemblerList_PopularityLost(ushort key, FileTransfer.FileStreamAssembler value) {
                value.Clear();
            }

            private void FileIdSegmentAssemblerList_PopularityLost(ushort key, FileTransfer.FileSegmentAssembler value) {
                value.Close();
            }

            internal string GetId() {
                return GetSmbSessionId(this.serverIP, serverTcpPort, clientIP, clientTcpPort);
            }

            internal bool ContainsFileId(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                this.Touch(treeId, muxId, processId, fileId);
                return this.fileIdAssemblerList.ContainsKey(fileId);
            }

            internal void AddFileStreamAssembler(FileTransfer.FileStreamAssembler assembler, ushort treeId, ushort muxId, ushort processId) {
                this.AddFileStreamAssembler(assembler, treeId, muxId, processId, (ushort)0);
            }
            internal void AddFileStreamAssembler(FileTransfer.FileStreamAssembler assembler, ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                this.lastReferencedFileIdPerTreeMux[Utils.ByteConverter.ToUInt32(treeId, muxId)] = fileId;
                this.lastReferencedFileIdPerPidMux[Utils.ByteConverter.ToUInt32(processId, muxId)] = fileId;
                if(this.fileIdAssemblerList.ContainsKey(fileId))
                    this.fileIdAssemblerList.Remove(fileId);
                this.fileIdAssemblerList.Add(fileId, assembler);
            }
            internal void AddFileSegmentAssembler(FileTransfer.FileSegmentAssembler assembler, ushort fileId) {
                this.fileIdSegmentAssemblerList.Add(fileId, assembler);
            }


            internal void RemoveLastReferencedAssembler(ushort treeId, ushort muxId, ushort processId) {
                ushort lastReferencedFileId;
                if (lastReferencedFileIdPerPidMux.ContainsKey(Utils.ByteConverter.ToUInt32(processId, muxId)))
                    lastReferencedFileId = lastReferencedFileIdPerPidMux[Utils.ByteConverter.ToUInt32(processId, muxId)];
                else if (lastReferencedFileIdPerTreeMux.ContainsKey(Utils.ByteConverter.ToUInt32(treeId, muxId)))
                    lastReferencedFileId = lastReferencedFileIdPerTreeMux[Utils.ByteConverter.ToUInt32(treeId, muxId)];
                else
                    lastReferencedFileId=(ushort)0;

                if(this.fileIdAssemblerList.ContainsKey(lastReferencedFileId))
                    this.RemoveFileStreamAssembler(treeId, muxId, processId, lastReferencedFileId);
            }
            internal void RemoveFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                RemoveFileStreamAssembler(treeId, muxId, processId, fileId, false);
            }
            internal void RemoveFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId, bool closeAssembler) {
                //this.Touch(treeId, muxId, fileId);
                if(this.fileIdAssemblerList.ContainsKey(fileId)) {
                    FileTransfer.FileStreamAssembler assembler=GetFileStreamAssembler(treeId, muxId, processId, fileId);
                    this.fileIdAssemblerList.Remove(fileId);
                    if(closeAssembler)
                        assembler.Clear();
                }
            }
            internal FileTransfer.FileStreamAssembler GetLastReferencedFileStreamAssembler(ushort treeId, ushort muxId, ushort processId) {
                if (lastReferencedFileIdPerPidMux.ContainsKey(Utils.ByteConverter.ToUInt32(processId, muxId)))
                    return GetFileStreamAssembler(treeId, muxId, processId, lastReferencedFileIdPerPidMux[Utils.ByteConverter.ToUInt32(processId, muxId)]);
                else if (lastReferencedFileIdPerTreeMux.ContainsKey(Utils.ByteConverter.ToUInt32(treeId, muxId)))
                    return GetFileStreamAssembler(treeId, muxId, processId, lastReferencedFileIdPerTreeMux[Utils.ByteConverter.ToUInt32(treeId, muxId)]);
                else
                    return null;
                //return GetFileStreamAssembler(lastReferencedFileId);
            }
            internal FileTransfer.FileStreamAssembler GetFileStreamAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId){
                //this.lastReferencedFileId=fileId;
                this.Touch(treeId, muxId, processId, fileId);

                if(this.fileIdAssemblerList.ContainsKey(fileId))
                    return this.fileIdAssemblerList[fileId];
                else
                    return null;
            }
            internal FileTransfer.FileSegmentAssembler GetFileSegmentAssembler(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                //this.lastReferencedFileId=fileId;
                this.Touch(treeId, muxId, processId, fileId);

                if (this.fileIdSegmentAssemblerList.ContainsKey(fileId))
                    return this.fileIdSegmentAssemblerList[fileId];
                else
                    return null;
            }

            /// <summary>
            /// Updates the fileId so that it will be referenced as "LastReferencedFile"
            /// </summary>
            /// <param name="fileId"></param>
            internal void Touch(ushort treeId, ushort muxId, ushort processId, ushort fileId) {
                //System.Diagnostics.Debug.Assert(this.fileIdAssemblerList.ContainsKey(fileId), "treeID="+treeId.ToString("X4")+" muxID="+muxId.ToString("X4")+" fileID="+fileId.ToString("X4"));
                if(this.fileIdAssemblerList.ContainsKey(fileId)) {
                    this.lastReferencedFileIdPerTreeMux[Utils.ByteConverter.ToUInt32(treeId, muxId)] = fileId;
                    this.lastReferencedFileIdPerPidMux[Utils.ByteConverter.ToUInt32(processId, muxId)] = fileId;
                }
            }

            internal void AddTreeConnectAndXRequestPath(ushort userID, ushort muxID, string path) {
                int key = (userID << 16) & muxID;
                if (this.lastTreeConnectAndXRequestPathPerUserMux.ContainsKey(key))
                    this.lastTreeConnectAndXRequestPathPerUserMux[(userID << 16) & muxID] = path;
                else
                    this.lastTreeConnectAndXRequestPathPerUserMux.Add(key, path);
            }

            internal void StoreTreeConnectAndXRequestPathForTree(ushort userID, ushort muxID, ushort treeId) {
                int key = (userID << 16) & muxID;
                if (this.lastTreeConnectAndXRequestPathPerUserMux.ContainsKey(key)) {
                    string path = this.lastTreeConnectAndXRequestPathPerUserMux[key];
                    if (this.treePathList.ContainsKey(treeId))
                        this.treePathList.Remove(treeId);
                    this.treePathList.Add(treeId, path);
                }
            }

            internal string GetPathForTree(ushort treeId) {
                if (this.treePathList.ContainsKey(treeId))
                    return this.treePathList[treeId];
                else
                    return null;
            }
        }
    }
}
