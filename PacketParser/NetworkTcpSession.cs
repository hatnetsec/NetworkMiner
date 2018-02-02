//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//


using System;
using System.Collections.Generic;

namespace PacketParser {
    public class NetworkTcpSession : IComparable {//only TCP sessions

        

        //private NetworkHost clientHost, serverHost;
        //private ushort clientTcpPort, serverTcpPort;

        //private DateTime synPacketTimestamp;//in NetworkFlow
        //private DateTime latestPacketTimestamp;//in NetworkFlow

        private long startFrameNumber;

        private bool synPacketReceived;
        private bool synAckPacketReceived;
        private bool finPacketReceived;
        private bool sessionEstablished;
        private bool sessionClosed;

        private uint clientToServerFinPacketSequenceNumber;
        private uint serverToClientFinPacketSequenceNumber;

        private TcpDataStream clientToServerTcpDataStream;
        private TcpDataStream serverToClientTcpDataStream;
        private bool? requiredNextTcpDataStreamIsClientToServer = null;

        private ISessionProtocolFinder protocolFinder;
        private NetworkFlow flow;

        public NetworkHost ClientHost { get { return this.flow.FiveTuple.ClientHost; } }
        public NetworkHost ServerHost { get { return this.flow.FiveTuple.ServerHost; } }
        public ushort ClientTcpPort { get { return this.flow.FiveTuple.ClientPort; } }
        public ushort ServerTcpPort { get { return this.flow.FiveTuple.ServerPort; } }
        public DateTime StartTime { get { return this.flow.StartTime;; } }//in NetworkFlow
        public DateTime EndTime { get { return this.flow.EndTime; } }//in NetworkFlow
        public bool SynPacketReceived { get { return this.synPacketReceived; } }
        public bool SynAckPacketReceived { get { return this.synAckPacketReceived; } }
        public bool FinPacketReceived {
            get {
                //https://sourceforge.net/projects/networkminer/forums/forum/665610/topic/4946533/index/page/1
                return this.finPacketReceived &&
                    (clientToServerTcpDataStream == null ||
                    serverToClientTcpDataStream == null ||
                    clientToServerTcpDataStream == null ||
                    (this.clientToServerFinPacketSequenceNumber <= clientToServerTcpDataStream.ExpectedTcpSequenceNumber && this.serverToClientFinPacketSequenceNumber < serverToClientTcpDataStream.ExpectedTcpSequenceNumber));
            }
        }
        public bool SessionEstablished { get { return this.sessionEstablished; } }
        public bool SessionClosed { get { return this.sessionClosed; } }
        public TcpDataStream ClientToServerTcpDataStream { get { return this.clientToServerTcpDataStream; } }
        public TcpDataStream ServerToClientTcpDataStream { get { return this.serverToClientTcpDataStream; } }
        public TcpDataStream RequiredNextTcpDataStream {
            get {
                if (this.requiredNextTcpDataStreamIsClientToServer == true)
                    return this.clientToServerTcpDataStream;
                else if (this.requiredNextTcpDataStreamIsClientToServer == false)
                    return this.serverToClientTcpDataStream;
                else
                    return null;
            }
            set {
                if (value == null)
                    this.requiredNextTcpDataStreamIsClientToServer = null;
            }
        }
        public ISessionProtocolFinder ProtocolFinder { get { return this.protocolFinder; } set { this.protocolFinder = value; } }
        public NetworkFlow Flow { get { return this.flow; } }

        public NetworkTcpSession(Packets.TcpPacket tcpSynPacket, NetworkHost clientHost, NetworkHost serverHost, ISessionProtocolFinderFactory protocolFinderFactory) {

            if(tcpSynPacket.FlagBits.Synchronize) {//It's normal to start the session with a SYN flag
                FiveTuple fiveTuple = new FiveTuple(clientHost, tcpSynPacket.SourcePort, serverHost, tcpSynPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.flow = new NetworkFlow(fiveTuple, tcpSynPacket.ParentFrame.Timestamp, tcpSynPacket.ParentFrame.Timestamp, 0, 0);
                //this.synPacketTimestamp=tcpSynPacket.ParentFrame.Timestamp;
                //this.clientHost=clientHost;
                //this.serverHost=serverHost;
                //this.clientTcpPort=tcpSynPacket.SourcePort;
                //this.serverTcpPort=tcpSynPacket.DestinationPort;

                this.synPacketReceived=false;
                this.synAckPacketReceived=false;
                this.finPacketReceived=false;
                this.clientToServerFinPacketSequenceNumber=UInt32.MaxValue;
                this.serverToClientFinPacketSequenceNumber=UInt32.MaxValue;
                this.sessionEstablished=false;
                this.sessionClosed=false;

                this.startFrameNumber = tcpSynPacket.ParentFrame.FrameNumber;

                this.clientToServerTcpDataStream=null;
                this.serverToClientTcpDataStream=null;


                this.protocolFinder = protocolFinderFactory.CreateProtocolFinder(this.flow, this.startFrameNumber);
            }
            else
                throw new Exception("SYN flag not set on TCP packet");

        }
        /// <summary>
        /// Creates a truncated TCP session where the initial 3 way handshake is missing
        /// </summary>
        /// <param name="sourceHost"></param>
        /// <param name="destinationHost"></param>
        /// <param name="tcpPacket"></param>
        public NetworkTcpSession(NetworkHost sourceHost, NetworkHost destinationHost, Packets.TcpPacket tcpPacket, ISessionProtocolFinderFactory protocolFinderFactory) {
            //this part is used to create a cropped (truncated) session where the beginning is missing!
            //this.synPacketTimestamp=tcpPacket.ParentFrame.Timestamp;
            this.synPacketReceived=true;
            this.synAckPacketReceived=true;
            this.finPacketReceived=false;
            this.sessionEstablished=false;//I will change this one soon,...
            this.sessionClosed=false;

            this.startFrameNumber = tcpPacket.ParentFrame.FrameNumber;

            this.clientToServerTcpDataStream=null;
            this.serverToClientTcpDataStream=null;


            //now let's do a qualified guess of who is the server and who is client...

            FiveTuple fiveTuple;
            System.Collections.Generic.List<ApplicationLayerProtocol> sourcePortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.SourcePort, tcpPacket.SourcePort));
            System.Collections.Generic.List<ApplicationLayerProtocol> destinationPortProtocols = new List<ApplicationLayerProtocol>(TcpPortProtocolFinder.GetProbableApplicationLayerProtocols(tcpPacket.DestinationPort, tcpPacket.DestinationPort));
            if(sourcePortProtocols.Count > destinationPortProtocols.Count) { //packet is server -> client
                //this.clientHost=destinationHost;
                //this.serverHost=sourceHost;
                //this.clientTcpPort=tcpPacket.DestinationPort;
                //this.serverTcpPort=tcpPacket.SourcePort;
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);
                
            }
            else if(destinationPortProtocols.Count > 0) { //packet is client -> server
                //this.clientHost=sourceHost;
                //this.serverHost=destinationHost;
                //this.clientTcpPort=tcpPacket.SourcePort;
                //this.serverTcpPort=tcpPacket.DestinationPort;
                
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort,  FiveTuple.TransportProtocol.TCP);
                this.flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }
            else if(tcpPacket.SourcePort<tcpPacket.DestinationPort) {//packet is server -> client
                //this.clientHost=destinationHost;
                //this.serverHost=sourceHost;
                //this.clientTcpPort=tcpPacket.DestinationPort;
                //this.serverTcpPort=tcpPacket.SourcePort;
                
                fiveTuple = new FiveTuple(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP);
                this.flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.AcknowledgmentNumber, tcpPacket.SequenceNumber);
            }
            else {//packet is client -> server
                //this.clientHost=sourceHost;
                //this.serverHost=destinationHost;
                //this.clientTcpPort=tcpPacket.SourcePort;
                //this.serverTcpPort=tcpPacket.DestinationPort;
                
                fiveTuple = new FiveTuple(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP);
                this.flow = new NetworkFlow(fiveTuple, tcpPacket.ParentFrame.Timestamp, tcpPacket.ParentFrame.Timestamp, 0, 0);
                this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
            }
            
            this.protocolFinder = protocolFinderFactory.CreateProtocolFinder(this.flow, this.startFrameNumber);
        }



        public string GetFlowID() {
            return this.ClientHost.IPAddress.ToString() + ":" + this.ClientTcpPort.ToString() + "-" + this.ServerHost.IPAddress.ToString() + ":" + this.ServerTcpPort.ToString();
        }

        public static int GetHashCode(NetworkHost clientHost, NetworkHost serverHost, ushort clientTcpPort, ushort serverTcpPort) {
            int cHash=clientHost.IPAddress.GetHashCode()^clientTcpPort;
            int sHash=serverHost.IPAddress.GetHashCode()^serverTcpPort;
            return cHash^(sHash<<16)^(sHash>>16);//this should be enough in order to avoid collisions
        }

        public override int GetHashCode() {
            return GetHashCode(this.ClientHost, this.ServerHost, this.ClientTcpPort, this.ServerTcpPort);
        }
        public override string ToString() {
            return "Server: "+this.ServerHost.ToString()+" TCP "+this.ServerTcpPort+" ("+this.serverToClientTcpDataStream.TotalByteCount+" data bytes sent), Client: "+this.ClientHost.ToString()+" TCP "+this.ClientTcpPort+" ("+this.clientToServerTcpDataStream.TotalByteCount+" data bytes sent), Session start: "+this.flow.StartTime.ToString("u")+", Session end: "+this.flow.EndTime.ToString("u");
        }

        public bool TryAddPacket(Packets.TcpPacket tcpPacket, NetworkHost sourceHost, NetworkHost destinationHost) {
            if(this.sessionClosed)
                return false;

            //Make sure the hosts are correct
            if(sourceHost==this.ClientHost && tcpPacket.SourcePort==this.ClientTcpPort) {//client -> server
                if(destinationHost!=this.ServerHost)
                    return false;
                if(tcpPacket.SourcePort!=this.ClientTcpPort)
                    return false;
                if(tcpPacket.DestinationPort!=this.ServerTcpPort)
                    return false;
            }
            else if(sourceHost==this.ServerHost && tcpPacket.SourcePort==this.ServerTcpPort) {//server -> client
                if(destinationHost!=ClientHost)
                    return false;
                if(tcpPacket.SourcePort!=ServerTcpPort)
                    return false;
                if(tcpPacket.DestinationPort!=ClientTcpPort)
                    return false;
            }
            else//unknown direction
                return false;

            //this.latestPacketTimestamp=tcpPacket.ParentFrame.Timestamp;
            this.flow.EndTime = tcpPacket.ParentFrame.Timestamp;

            //Check TCP handshake
            if (!this.synPacketReceived) {//SYN (client->server)
                if(tcpPacket.FlagBits.Synchronize && sourceHost==this.ClientHost)
                    this.synPacketReceived=true;
                else
                    return false;
            }
            else if(!this.synAckPacketReceived) {//SYN+ACK (server->client)
                if(tcpPacket.FlagBits.Synchronize && tcpPacket.FlagBits.Acknowledgement && sourceHost==this.ServerHost)
                    this.synAckPacketReceived=true;
                else
                    return false;
            }
            else if(!this.sessionEstablished) {//ACK (client->server)
                if(tcpPacket.FlagBits.Acknowledgement && sourceHost==this.ClientHost) {
                    this.SetEstablished(tcpPacket.SequenceNumber, tcpPacket.AcknowledgmentNumber);
                }
                else
                    return false;
            }
            //FIN and RST is handeled lower down 


            //else{//an established and not closed session!
            if(tcpPacket.PayloadDataLength>0) {
                this.protocolFinder.AddPacket(tcpPacket, sourceHost, destinationHost);
                try {
                    //If we've come this far the packet should be allright for the networkSession
                    byte[] tcpSegmentData=tcpPacket.GetTcpPacketPayloadData();


                    //now add the data to the server to calculate service statistics for the open port
                    NetworkServiceMetadata networkServiceMetadata=null;
                    lock (this.ServerHost.NetworkServiceMetadataList) {
                        if (!this.ServerHost.NetworkServiceMetadataList.ContainsKey(this.ServerTcpPort)) {
                            networkServiceMetadata = new NetworkServiceMetadata(this.ServerHost, this.ServerTcpPort);
                            this.ServerHost.NetworkServiceMetadataList.Add(this.ServerTcpPort, networkServiceMetadata);
                        }
                        else
                            networkServiceMetadata = this.ServerHost.NetworkServiceMetadataList[this.ServerTcpPort];
                    }

                    //now, lets extract some data from the TCP packet!
                    if(sourceHost==this.ServerHost && tcpPacket.SourcePort==this.ServerTcpPort) {
                        networkServiceMetadata.OutgoingTraffic.AddTcpPayloadData(tcpSegmentData);
                        //this.clientToServerTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData);
                        if(this.serverToClientTcpDataStream==null)
                            this.serverToClientTcpDataStream=new TcpDataStream(tcpPacket.SequenceNumber, false, this);
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.serverToClientTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = false;
                        this.serverToClientTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData);
                    }
                    else {
                        networkServiceMetadata.IncomingTraffic.AddTcpPayloadData(tcpSegmentData);
                        //this.serverToClientTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData);
                        if(this.clientToServerTcpDataStream==null)
                            this.clientToServerTcpDataStream = new TcpDataStream(tcpPacket.SequenceNumber,true, this);
                        if (this.requiredNextTcpDataStreamIsClientToServer == null && this.clientToServerTcpDataStream.TotalByteCount == 0)
                            this.requiredNextTcpDataStreamIsClientToServer = true;
                        this.clientToServerTcpDataStream.AddTcpData(tcpPacket.SequenceNumber, tcpSegmentData);
                    }
                }
                catch(Exception ex) {
                    if (!tcpPacket.ParentFrame.QuickParse)
                        tcpPacket.ParentFrame.Errors.Add(new Frame.Error(tcpPacket.ParentFrame, tcpPacket.PacketStartIndex, tcpPacket.PacketEndIndex, ex.Message));
                    return false;
                }
            }
            //}

            //se if stream should be closed
            if(tcpPacket.FlagBits.Reset){//close no matter what
                this.Close();
            }
            else if(tcpPacket.FlagBits.Fin){//close nicely
                if(!this.finPacketReceived) {
                    this.finPacketReceived=true;
                    if(sourceHost==this.ServerHost && tcpPacket.SourcePort==this.ServerTcpPort)
                        this.serverToClientFinPacketSequenceNumber=tcpPacket.SequenceNumber;
                    else
                        this.clientToServerFinPacketSequenceNumber=tcpPacket.SequenceNumber;
                }
                else if(tcpPacket.FlagBits.Acknowledgement)//fin+ack
                    this.Close();
            }

            return true;
        }

        
        internal void RemoveData(TcpDataStream.VirtualTcpData virtualTcpData, NetworkHost sourceHost, ushort sourceTcpPort) {
            this.RemoveData(virtualTcpData.FirstPacketSequenceNumber, virtualTcpData.ByteCount, sourceHost, sourceTcpPort);

        }

        internal void RemoveData(uint firstSequenceNumber, int bytesToRemove, NetworkHost sourceHost, ushort sourceTcpPort) {
            if(sourceHost==this.ServerHost && sourceTcpPort==this.ServerTcpPort)
                this.ServerToClientTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else if(sourceHost==this.ClientHost && sourceTcpPort==this.ClientTcpPort)
                this.ClientToServerTcpDataStream.RemoveData(firstSequenceNumber, bytesToRemove);
            else
                throw new Exception("NetworkHost is not part of the NetworkTcpSession");
        }

        private void SetEstablished(uint clientInitialSequenceNumber, uint serverInitialSequenceNumber) {
            this.sessionEstablished=true;
            if(this.clientToServerTcpDataStream==null)
                this.clientToServerTcpDataStream = new TcpDataStream(clientInitialSequenceNumber, true, this);
            else
                this.clientToServerTcpDataStream.InitialTcpSequenceNumber=clientInitialSequenceNumber;
            if(this.serverToClientTcpDataStream==null)
                this.serverToClientTcpDataStream = new TcpDataStream(serverInitialSequenceNumber, false, this);
            else
                this.serverToClientTcpDataStream.InitialTcpSequenceNumber=serverInitialSequenceNumber;
            lock(this.ServerHost.IncomingSessionList)
                this.ServerHost.IncomingSessionList.Add(this);
            lock(this.ClientHost.OutgoingSessionList)
                this.ClientHost.OutgoingSessionList.Add(this);

        }

        internal void Close() {
            //this.clientToServerTcpDataStream.Close();
            //this.serverToClientTcpDataStream.Close();
            this.sessionClosed=true;

            if(this.protocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.Unknown)
                this.protocolFinder.SetConfirmedApplicationLayerProtocol(ApplicationLayerProtocol.Unknown, false);
        }


        #region IComparable Members

        public int CompareTo(NetworkTcpSession session) {
            if(this.ClientHost.CompareTo(session.ClientHost)!=0)
                return this.ClientHost.CompareTo(session.ClientHost);
            else if(this.ServerHost.CompareTo(session.ServerHost)!=0)
                return this.ServerHost.CompareTo(session.ServerHost);
            else if(this.ClientTcpPort!=session.ClientTcpPort)
                return this.ClientTcpPort-session.ClientTcpPort;
            else if(this.ServerTcpPort!=session.ServerTcpPort)
                return this.ServerTcpPort-session.ServerTcpPort;
            else if(this.StartTime.CompareTo(session.StartTime)!=0)
                return this.StartTime.CompareTo(session.StartTime);
            else
                return 0;
        }
        public int CompareTo(object obj) {
            NetworkTcpSession s=(NetworkTcpSession)obj;
            return CompareTo(s);
        }

        #endregion

        public class TcpDataStream{

            private uint initialTcpSequenceNumber;
            private uint expectedTcpSequenceNumber;//the sequence number the next TCP packet from the server is expected to have. Hence the data is complete from the initial sequence number to this number
            //private ushort sourcePort, destinationPort;

            private System.Collections.Generic.SortedList<uint, byte[]> dataList;
            private int dataListMaxSize;
            private bool dataListIsTruncated = false;

            //private int totalByteCount;//we have this data in networkFlow already
            private VirtualTcpData virtualTcpData;
            private NetworkTcpSession session;
            private NetworkFlow networkFlow;
            private bool streamIsClientToServer;

            //public int TotalByteCount { get { return this.totalByteCount; } }
            public long TotalByteCount { get {
                    if (this.streamIsClientToServer)
                        return this.networkFlow.BytesSentClient;
                    else
                        return this.networkFlow.BytesSentServer;
                }
                set {
                    if (this.streamIsClientToServer)
                        this.networkFlow.BytesSentClient = value;
                    else
                        this.networkFlow.BytesSentServer = value;
                }
            }
            public int DataSegmentBufferCount { get { return this.dataList.Count; } }
            public int DataSegmentBufferMaxSize { get { return this.dataListMaxSize; } }

            internal uint InitialTcpSequenceNumber { set { this.initialTcpSequenceNumber=value; } }
            internal uint ExpectedTcpSequenceNumber { get { return this.expectedTcpSequenceNumber; } }

            
            public TcpDataStream(uint initialTcpSequenceNumber, bool streamIsClientToServer, NetworkTcpSession session) {
                this.initialTcpSequenceNumber=initialTcpSequenceNumber;
                this.expectedTcpSequenceNumber=initialTcpSequenceNumber;
                //this.sourcePort=sourcePort;
                //this.destinationPort=destinationPort;
                this.dataList=new SortedList<uint, byte[]>();
                //this.dataListMaxSize=64;//i hope I shouldn't need more than 64 packets in the list. It depends on how late a misordered packet might get received. Smaller number gives better performance, larger number gives better tolerance to reordered packets
                this.dataListMaxSize = 256;//allows data packets to be out-of-order up to 256 packets apart from each other in the same unidirectional stream
      
                //this.totalByteCount=0;
                this.virtualTcpData=null;
                this.session = session;
                this.networkFlow = session.Flow;
                //this.protocolFinder = session.protocolFinder;
                this.streamIsClientToServer = streamIsClientToServer;
            }

            [Obsolete]
            internal bool HasMissingSegments() {
                //return totalByteCount<this.expectedTcpSequenceNumber-this.initialTcpSequenceNumber;
                return  this.TotalByteCount<this.expectedTcpSequenceNumber-this.initialTcpSequenceNumber;
            }

            public void AddTcpData(uint tcpSequenceNumber, byte[] tcpSegmentData) {

                if(tcpSegmentData.Length>0) {//It is VERY important that no 0 length data arrays are added! There is otherwise a big risk for getting stuck in forever-loops etc.

                    //ensure that only new data is written to the dataList
                    //partially overlapping resent frames are handled here
                    if((int)(expectedTcpSequenceNumber-tcpSequenceNumber)>0 && expectedTcpSequenceNumber-tcpSequenceNumber<tcpSegmentData.Length) {
                        //remove the stuff that has already been parsed
                        uint bytesToSkip=expectedTcpSequenceNumber-tcpSequenceNumber;
                        byte[] newSegmentData=new byte[tcpSegmentData.Length-bytesToSkip];
                        Array.Copy(tcpSegmentData, bytesToSkip, newSegmentData, 0, newSegmentData.Length);
                        tcpSegmentData=newSegmentData;
                        tcpSequenceNumber+=bytesToSkip;
                    }
                    //see if we've missed part of the handshake and are now seeing the first data with lower sequence number
                    if (this.TotalByteCount == 0 && initialTcpSequenceNumber == expectedTcpSequenceNumber && (int)(expectedTcpSequenceNumber - tcpSequenceNumber) > 0 && (int)(tcpSequenceNumber - expectedTcpSequenceNumber) < 12345) {
                        this.initialTcpSequenceNumber = tcpSequenceNumber;
                        this.expectedTcpSequenceNumber = tcpSequenceNumber;
                    }
                    //A check that the tcpSequenceNumber is a reasonable one, i.e. not smaller than expected and not too large
                    if ((int)(expectedTcpSequenceNumber-tcpSequenceNumber)<=0 && tcpSequenceNumber-expectedTcpSequenceNumber<1234567) {



                        if(!dataList.ContainsKey(tcpSequenceNumber)) {
                            
                            //handle partially overlapping TCP segments that have arrived previously
                            IList<uint> tcpSequenceNumbers = dataList.Keys;
                            //we wanna know if we already have an already stored sequence nr. where: new tcpSeqNr < stored tcpSeqNr < new tcpSeqNr + new tcpSeqData.Length
                            
                            /*
                            //METHOD #1
                            for (int i = 0; i < tcpSequenceNumbers.Count; i++) { //this part should be replaced by a binary search function to reduce complexity
                                if (tcpSequenceNumbers[i] > tcpSequenceNumber) {
                                    if (tcpSequenceNumbers[i] < tcpSequenceNumber + tcpSegmentData.Length) {
                                        //we need to truncate the data since parts of it has already been received
                                        uint bytesToKeep = tcpSequenceNumbers[i] - tcpSequenceNumber;
                                        byte[] newSegmentData = new byte[bytesToKeep];
                                        Array.Copy(tcpSegmentData, 0, newSegmentData, 0, bytesToKeep);
                                        tcpSegmentData = newSegmentData;
                                    }
                                    break;
                                }
                            }
                             * */
                            
                            
                            //METHOD #2
                            for (int i = tcpSequenceNumbers.Count - 1; i >= 0; i--) {
                                if (tcpSequenceNumbers[i] < tcpSequenceNumber)
                                    break;
                                else if (tcpSequenceNumbers[i] < tcpSequenceNumber + tcpSegmentData.Length) {
                                    //we need to truncate the data since parts of it has already been received
                                    uint bytesToKeep = tcpSequenceNumbers[i] - tcpSequenceNumber;
                                    byte[] newSegmentData = new byte[bytesToKeep];
                                    Array.Copy(tcpSegmentData, 0, newSegmentData, 0, bytesToKeep);
                                    tcpSegmentData = newSegmentData;
                                }
                            }
                            //avoid addint TCP keep-alive null-data (one byte)
                            // a keepalive contains 0 or 1 bytes of data and has a sequence nr that is next_expected-1, never SYN/FIN/RST
                            //if (tcpSegmentData.Length == 1 && tcpSegmentData[0] == 0)
                            //    System.Diagnostics.Debugger.Break();

                            //Avoid adding TCP data for TCP-keepalives with "fake" one-byte L7 data (null value)
                            if (tcpSegmentData.Length > 1 || tcpSegmentData[0] != 0 || this.TotalByteCount > 0) {
                                dataList.Add(tcpSequenceNumber, tcpSegmentData);
                                this.TotalByteCount += tcpSegmentData.Length;
                            }
                            
                            if(expectedTcpSequenceNumber==tcpSequenceNumber) {
                                expectedTcpSequenceNumber+=(uint)tcpSegmentData.Length;
                                //check if there are other packets that arrived too early that follows this packet
                                while(dataList.ContainsKey(expectedTcpSequenceNumber))
                                    expectedTcpSequenceNumber+=(uint)dataList[expectedTcpSequenceNumber].Length;
                            }

                            while(dataList.Count>this.dataListMaxSize) {
                                if (!this.dataListIsTruncated) {
                                    Utils.Logger.Log("Too many unparsed queued packets, queue will be truncated for : " + this.networkFlow.FiveTuple.ToString(), System.Diagnostics.EventLogEntryType.Warning);
#if DEBUG
                                    if (!debugHasBreaked) {
                                        System.Diagnostics.Debugger.Break();
                                        debugHasBreaked = true;
                                    }
#endif
                                }
                                dataList.RemoveAt(0);//remove the oldest TCP data
                                this.dataListIsTruncated = true;
                                this.virtualTcpData=null;//this one has to be reset so that the virtualPacket still will work
                            }
                        }
                        else {//let's replace the old TCP packet with the new one
                            //Or maybe just skip it!
                        }
                    }
                }
            }

#if DEBUG
            static bool debugHasBreaked = false;
#endif


            /// <summary>
            /// Counts the number of bytes which are ready for reading (that is are in the correct order).
            /// Time complexity = O(1)
            /// </summary>
            /// <returns></returns>
            public int CountBytesToRead() {
                if(dataList.Count<1)
                    return 0;
                else{
                    return (int)this.expectedTcpSequenceNumber-(int)this.dataList.Keys[0];
                }
            }

            /// <summary>
            /// Counts the number of packets from the start that are in one complete sequence
            /// Time complexity = O(nPacketsInSequence)
            /// </summary>
            /// <returns></returns>
            public int CountPacketsToRead() {
                //this method does not always return daatList.Count since some packets in the dataList might be out of order or missing
                
                if(dataList.Count==0)
                    return 0;
                else {
                    int nPackets=0;
                    uint nextSequenceNumber=dataList.Keys[0];
                    foreach(KeyValuePair<uint, byte[]> pair in this.dataList)
                        if(pair.Key==nextSequenceNumber) {
                            nPackets++;
                            nextSequenceNumber+=(uint)pair.Value.Length;
                        }
                        else
                            break;
                    return nPackets;
                }
            }

            internal VirtualTcpData GetNextVirtualTcpData() {
                if(this.virtualTcpData==null) {
                    if(this.dataList.Count>0 && this.CountBytesToRead()>0 && this.CountPacketsToRead()>0) {
                        if(this.streamIsClientToServer)
                            this.virtualTcpData=new VirtualTcpData(this, this.networkFlow.FiveTuple.ClientPort, this.networkFlow.FiveTuple.ServerPort);
                        else
                            this.virtualTcpData = new VirtualTcpData(this, this.networkFlow.FiveTuple.ServerPort, this.networkFlow.FiveTuple.ClientPort);
                        return virtualTcpData;
                    }
                    else
                        return null;
                }
                else if(virtualTcpData.TryAppendNextPacket())
                        return virtualTcpData;
                else
                    return null;
            }

            /// <summary>
            /// Removes sequenced data from the beginning
            /// </summary>
            /// <param name="bytesToRemove"></param>
            internal void RemoveData(int bytesToRemove) {
                if (this.dataList.Count > 0)
                    this.RemoveData(this.dataList.Keys[0], bytesToRemove);
            }

            internal void RemoveData(VirtualTcpData data) {
                this.RemoveData(data.FirstPacketSequenceNumber, data.ByteCount);
            }

            internal void RemoveData(uint firstSequenceNumber, int bytesToRemove) {
                if(this.dataList.Keys[0]!=firstSequenceNumber)
                    throw new Exception("The data (first data sequence number: "+this.dataList.Keys[0]+") is not equal to "+firstSequenceNumber);
                else {
                    while(this.dataList.Count>0 && this.dataList.Keys[0]+this.dataList.Values[0].Length<=firstSequenceNumber+bytesToRemove)
                        this.dataList.RemoveAt(0);
                    //see if we need to do a partial removal of a tcp packet
                    if(this.dataList.Count>0 && this.dataList.Keys[0]<firstSequenceNumber+bytesToRemove) {
                        uint newFirstSequenceNumber = firstSequenceNumber+(uint)bytesToRemove;
                        byte[] oldData=this.dataList.Values[0];
                        byte[] truncatedData=new byte[this.dataList.Keys[0]+oldData.Length-newFirstSequenceNumber];
                        Array.Copy(oldData, oldData.Length-truncatedData.Length, truncatedData, 0, truncatedData.Length);
                        this.dataList.RemoveAt(0);
                        this.dataList.Add(newFirstSequenceNumber, truncatedData);
                    }
                    this.virtualTcpData=null;
                }

            }

            /// <summary>
            /// Enumerates all segments (that are in a complete sequence) and removes them from the NetworkTcpSession.TcpDataStream object
            /// </summary>
            /// <returns></returns>
            public IEnumerable<byte[]> GetSegments() {
                if(dataList.Count<1)
                    yield break;
                else {
                    for(uint nextSegmentSequenceNumber=dataList.Keys[0]; nextSegmentSequenceNumber<this.expectedTcpSequenceNumber; nextSegmentSequenceNumber=dataList.Keys[0] ) {
                        byte[] segment;
                        if(dataList.TryGetValue(nextSegmentSequenceNumber, out segment)) {
                            dataList.Remove(dataList.Keys[0]);
                            yield return segment;
                            if (dataList.Count == 0)
                                break;
                        }
                        else {
                            yield break;
                            //break;//this line might not be needed...
                        }
                    }

                }
            }

            internal class VirtualTcpData {
                private TcpDataStream tcpDataStream;
                //private System.Collections.Generic.SortedList<uint, byte[]> dataPacketList;
                private ushort sourcePort, destinationPort;
                private int nPackets;
                //private uint firstPacketSequenceNumber;//used in order to check that the dataList hasn't been changed!

                internal int PacketCount { get { return this.nPackets; } }
                internal int ByteCount { get { return (int)(this.tcpDataStream.dataList.Keys[nPackets-1]+(uint)this.tcpDataStream.dataList.Values[nPackets-1].Length-tcpDataStream.dataList.Keys[0]); } }
                internal uint FirstPacketSequenceNumber { get { return this.tcpDataStream.dataList.Keys[0]; } }


                //internal VirtualTcpData(System.Collections.Generic.SortedList<uint, byte[]> dataPacketList, ushort sourcePort, ushort destinationPort) {
                internal VirtualTcpData(TcpDataStream tcpDataStream, ushort sourcePort, ushort destinationPort) {
                    this.tcpDataStream=tcpDataStream;
                    this.sourcePort=sourcePort;
                    this.destinationPort=destinationPort;
                    this.nPackets=1;
                    //this.firstPacketSequenceNumber=tcpDataStream.dataList.Keys[0];
                }

                internal bool TryAppendNextPacket() {

                    int maxPacketFragments = 6;//this one is set low in order to get better performance
                    if (this.tcpDataStream.session.protocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.NetBiosSessionService)
                        maxPacketFragments = 50;//Changed 2011-04-25
                    else if (this.tcpDataStream.session.protocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.Http)
                        maxPacketFragments = 32;//Changed 2011-10-12 to handle AOL webmail
                    else if (this.tcpDataStream.session.protocolFinder.GetConfirmedApplicationLayerProtocol() == ApplicationLayerProtocol.Smtp)
                        maxPacketFragments = 61;//Changed 2014-04-07to handle short manual SMTP emails, such as when sending via Telnet (Example: M57 net-2009-11-16-09:24.pcap)
                    
                    if(tcpDataStream.CountBytesToRead()>this.ByteCount && tcpDataStream.CountPacketsToRead()>nPackets && nPackets<maxPacketFragments) {
                        nPackets++;
                        return true;//everything went just fine
                    }
                    else
                        return false;
                }

                private byte[] GetTcpHeader() {
                    byte[] tcpHeader=new byte[20];
                    Utils.ByteConverter.ToByteArray(sourcePort, tcpHeader, 0);
                    Utils.ByteConverter.ToByteArray(destinationPort, tcpHeader, 2);
                    Utils.ByteConverter.ToByteArray(tcpDataStream.dataList.Keys[0], tcpHeader, 4);
                    //skip ack.nr.
                    tcpHeader[12]=0x50;//5 words (5x4=20 bytes) TCP header
                    tcpHeader[13]=0x18;//flags: ACK+PSH
                    tcpHeader[14]=0xff;//window size 1
                    tcpHeader[15]=0xff;//window size 2
                    //calculate TCP checksum!
                    //i'll skip the checksum since I don't have an IP packet (IP source and destination is needed to calculate the checksum

                    //skip urgent pointer
                    return tcpHeader;
                }

                internal byte[] GetBytes(bool prependTcpHeader) {
                    List<byte> dataByteList;
                    if(prependTcpHeader)
                        dataByteList=new List<byte>(GetTcpHeader());
                    else
                        dataByteList=new List<byte>();
                    int tcpHeaderBytes=dataByteList.Count;
                    int packetsInByteList=0;
                    for(uint sequenceNumber=this.tcpDataStream.dataList.Keys[0]; packetsInByteList<this.nPackets; sequenceNumber=this.tcpDataStream.dataList.Keys[0]+(uint)dataByteList.Count-(uint)tcpHeaderBytes) {
                        dataByteList.AddRange(this.tcpDataStream.dataList[sequenceNumber]);//this one will generate an Exception if the sequence number isn't in the list; just as I want it to behave
                        packetsInByteList++;
                    }

                    return dataByteList.ToArray();
                }

            }
        }
    }
}
