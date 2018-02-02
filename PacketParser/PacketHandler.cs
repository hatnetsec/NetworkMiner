//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Net;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser {

    //internal delegate void NewNetworkHostHandler(NetworkHost host);
    public delegate void AnomalyEventHandler(object sender, Events.AnomalyEventArgs ae);
    public delegate void ParameterEventHandler(object sender, Events.ParametersEventArgs pe);
    public delegate void NetworkHostEventHandler(object sender, Events.NetworkHostEventArgs he);
    public delegate void HttpClientEventHandler(object sender, Events.HttpClientEventArgs he);
    public delegate void DnsRecordEventHandler(object sender, Events.DnsRecordEventArgs de);
    public delegate void BufferUsageEventHandler(object sender, Events.BufferUsageEventArgs be);
    public delegate void FrameEventHandler(object sender, Events.FrameEventArgs fe);
    public delegate void CleartextWordsEventHandler(object sender, Events.CleartextWordsEventArgs ce);
    public delegate void FileEventHandler(object sender, Events.FileEventArgs fe);
    public delegate void KeywordEventHandler(object sender, Events.KeywordEventArgs ke);
    public delegate void CredentialEventHandler(object sender, Events.CredentialEventArgs ce);
    public delegate void SessionEventHandler(object sender, Events.SessionEventArgs se);
    public delegate void MessageEventHandler(object sender, Events.MessageEventArgs me);



    public class PacketHandler {
        internal static PopularityList<string, List<Packets.IPv4Packet>> Ipv4Fragments = new PopularityList<string,List<Packets.IPv4Packet>>(1024);

        private NetworkHostList networkHostList;
        private long nFramesReceived, nBytesReceived;
        private List<Fingerprints.IOsFingerprinter> osFingerprintCollectionList;
        private CleartextDictionary.WordDictionary dictionary;
        
        private PopularityList<int, NetworkTcpSession> networkTcpSessionList;
        private FileTransfer.FileStreamAssemblerList fileStreamAssemblerList;
        private List<FileTransfer.ReconstructedFile> reconstructedFileList;
        private SortedList<string, NetworkCredential> credentialList;
        //TODO: Add PopularityList of type <FileSegmentAssembler>

        private System.Collections.Generic.Queue<NetworkWrapper.PacketReceivedEventArgs> receivedPacketsQueue;
        public const int RECEIVED_PACKETS_QUEUE_MAX_SIZE=16000;
        

        private System.Collections.Generic.Queue<Frame> framesToParseQueue;

        private byte[][] keywordList;
        private int cleartextSearchModeSelectedIndex;

        private int? lastBufferUsagePercent;

        //configurable settings
        private string outputDirectory;
        private bool defangExecutableFiles;
        private bool extractPartialDownloads = true;//defaults to true

        //Packet handlers
        private List<PacketHandlers.IPacketHandler> nonIpPacketHandlerList;//protocols in frames without IP packets
        private List<PacketHandlers.IPacketHandler> packetHandlerList;
        private List<PacketHandlers.ITcpSessionPacketHandler> tcpSessionPacketHandlerList;

        //Threads
        private System.Threading.Thread packetQueueConsumerThread;
        private System.Threading.Thread frameQueueConsumerThread;

        //Protocol Finder Factory
        private ISessionProtocolFinderFactory protocolFinderFactory;

        //Packet filter
        private IPacketFilter inputFilter = null;

        private PacketHandlers.IHttpPacketHandler extraHttpPacketHandler = null;

        //System.Threading.AutoResetEvent framesToParseQueueEvent, receivedPacketsQueueEvent;
        private Utils.QueueThresholdSignaller<Frame> framesToParseThresholdSignaller = null;
        private object insufficientWritePermissionsLock = new object();

        public event AnomalyEventHandler AnomalyDetected;
        public event ParameterEventHandler ParametersDetected;
        public event NetworkHostEventHandler NetworkHostDetected;
        public event HttpClientEventHandler HttpTransactionDetected;
        public event DnsRecordEventHandler DnsRecordDetected;
        public event BufferUsageEventHandler BufferUsageChanged;
        public event FrameEventHandler FrameDetected;
        public event CleartextWordsEventHandler CleartextWordsDetected;
        public event FileEventHandler FileReconstructed;
        public event KeywordEventHandler KeywordDetected;
        public event CredentialEventHandler CredentialDetected;
        public event SessionEventHandler SessionDetected;
        public event MessageEventHandler MessageDetected;
        public event FileTransfer.FileStreamAssembler.FileReconsructedEventHandler MessageAttachmentDetected;
        public event UnhandledExceptionEventHandler UnhandledException;
        public event Action<string> InsufficientWritePermissionsDetected;

        public byte[][] KeywordList { set { this.keywordList=value; } }
        public int CleartextSearchModeSelectedIndex { set { this.cleartextSearchModeSelectedIndex=value; } }

        public CleartextDictionary.WordDictionary Dictionary { set { this.dictionary=value; } }
        public List<Fingerprints.IOsFingerprinter> OsFingerprintCollectionList { get { return this.osFingerprintCollectionList; } }
        //internal ICollection<NetworkHost> DetectedHosts { get { return networkHostList.Hosts; } }
        public NetworkHostList NetworkHostList { get { return this.networkHostList; } }
        //internal NetworkMinerForm ParentForm { get { return this.parentForm; } }
        public FileTransfer.FileStreamAssemblerList FileStreamAssemblerList { get { return this.fileStreamAssemblerList; } }
        public int PacketsInQueue { get { return this.receivedPacketsQueue.Count; } }
        public int FramesInQueue { get { return this.framesToParseQueue.Count; } }

        public List<FileTransfer.ReconstructedFile> ReconstructedFileList { get { return this.reconstructedFileList; } }
        public ISessionProtocolFinderFactory ProtocolFinderFactory {
            get { return this.protocolFinderFactory; }
            set { this.protocolFinderFactory = value; }
        }

        public IPacketFilter InputFilter {
            get { return this.inputFilter; }
            set { this.inputFilter = value; }
        }

        public PacketHandlers.IHttpPacketHandler ExtraHttpPacketHandler {
            get { return this.extraHttpPacketHandler; }
            set { this.extraHttpPacketHandler = value; }
        }

        public string OutputDirectory { get { return this.outputDirectory; } }
        public bool DefangExecutableFiles {
            get { return this.defangExecutableFiles; }
            set { this.defangExecutableFiles = value; }
        }
        public bool ExtractPartialDownloads {
            get { return this.extractPartialDownloads; }
            set { this.extractPartialDownloads = value; }
        }

        public void ResetCapturedData() {
            lock (this.receivedPacketsQueue) {
                lock (this.networkHostList)
                    this.networkHostList.Clear();
                nFramesReceived = 0;
                nBytesReceived = 0;
                //lock(this.receivedFramesQueue)
                //    this.receivedFramesQueue.Clear();
                this.fileStreamAssemblerList.ClearAll();
                this.networkTcpSessionList.Clear();
                lock (Ipv4Fragments)
                    Ipv4Fragments.Clear();
                lock (this.reconstructedFileList)
                    this.reconstructedFileList.Clear();
                lock (this.credentialList)
                    this.credentialList.Clear();
                this.lastBufferUsagePercent = null;

                foreach (PacketHandlers.IPacketHandler packetHandler in this.packetHandlerList)
                    packetHandler.Reset();
                foreach (PacketHandlers.ITcpSessionPacketHandler packetHandler in this.tcpSessionPacketHandlerList)
                    packetHandler.Reset();

                this.receivedPacketsQueue.Clear();
            }
            if (this.extraHttpPacketHandler != null)
                this.extraHttpPacketHandler.Reset();
        }

#if DEBUG

        public void Disable() {
            this.AnomalyDetected += (o, k) => { System.Diagnostics.Debugger.Break();  throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.ParametersDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.NetworkHostDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.HttpTransactionDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.DnsRecordDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.BufferUsageChanged += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.FrameDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.CleartextWordsDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.FileReconstructed += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.KeywordDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.CredentialDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.SessionDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.MessageDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
            this.MessageAttachmentDetected += (o, k) => { System.Diagnostics.Debugger.Break(); throw new ObjectDisposedException("This PacketHandler is disabled, use a different one!"); };
        }
#endif


        public PacketHandler(string applicationExecutablePath, string outputPath, List<Fingerprints.IOsFingerprinter> preloadedFingerprints, bool ignoreMissingFingerprintFiles) {

            this.protocolFinderFactory = new PortProtocolFinderFactory(this);
            //this.parentForm=parentForm;

            this.networkHostList=new NetworkHostList();
            this.nFramesReceived=0;
            this.nBytesReceived=0;
            //this.receivedFramesQueue=new LatestFramesQueue(256);
            this.dictionary=new CleartextDictionary.WordDictionary();
            this.lastBufferUsagePercent=null;

            this.receivedPacketsQueue=new Queue<NetworkWrapper.PacketReceivedEventArgs>(RECEIVED_PACKETS_QUEUE_MAX_SIZE);
            this.framesToParseQueue=new Queue<Frame>(RECEIVED_PACKETS_QUEUE_MAX_SIZE);

            
            this.packetQueueConsumerThread=new System.Threading.Thread(new System.Threading.ThreadStart(delegate() { this.CreateFramesFromPacketsInPacketQueue(); }));
            this.frameQueueConsumerThread=new System.Threading.Thread(new System.Threading.ThreadStart(delegate() { this.ParseFramesInFrameQueue(); }));

            //this.framesToParseQueueEvent = new System.Threading.AutoResetEvent(false);
            //this.receivedPacketsQueueEvent = new System.Threading.AutoResetEvent(false);

            string applicationDirectory = Path.GetDirectoryName(applicationExecutablePath) + System.IO.Path.DirectorySeparatorChar;
            if (!outputPath.EndsWith(System.IO.Path.DirectorySeparatorChar.ToString()))
                outputPath += System.IO.Path.DirectorySeparatorChar.ToString();
            this.outputDirectory = Path.GetDirectoryName(outputPath) + System.IO.Path.DirectorySeparatorChar;
            this.osFingerprintCollectionList=new List<Fingerprints.IOsFingerprinter>();
            if (preloadedFingerprints != null)
                this.osFingerprintCollectionList.AddRange(preloadedFingerprints);

            //the ettercap fingerprints aren't needed
            try {
                osFingerprintCollectionList.Add(new Fingerprints.EttarcapOsFingerprintCollection(applicationDirectory + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "etter.finger.os"));//, NetworkMiner.Fingerprints.EttarcapOsFingerprintCollection.OsFingerprintFileFormat.Ettercap)
            }
            catch (FileNotFoundException) { }
            try {
                //Check CERT NetSA p0f database https://tools.netsa.cert.org/confluence/display/tt/p0f+fingerprints
                string netsaP0fFile = applicationDirectory + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "p0f.fp.netsa";
                if (System.IO.File.Exists(netsaP0fFile))
                    osFingerprintCollectionList.Add(new Fingerprints.P0fOsFingerprintCollection(netsaP0fFile, applicationDirectory + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "p0fa.fp", "p0f (NetSA)", 0.4));
                else
                    osFingerprintCollectionList.Add(new Fingerprints.P0fOsFingerprintCollection(applicationDirectory + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "p0f.fp", applicationDirectory + System.IO.Path.DirectorySeparatorChar + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "p0fa.fp"));
                osFingerprintCollectionList.Add(new Fingerprints.SatoriDhcpOsFingerprinter(applicationDirectory + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "dhcp.xml"));
                osFingerprintCollectionList.Add(new Fingerprints.SatoriTcpOsFingerprinter(applicationDirectory + "Fingerprints" + System.IO.Path.DirectorySeparatorChar + "tcp.xml"));
            }
            catch (FileNotFoundException e) {
                if (!ignoreMissingFingerprintFiles)
                    throw e;//re-throw the exception
            }
            //this.networkTcpSessionDictionary=new Dictionary<int, NetworkTcpSession>();
            this.networkTcpSessionList=new PopularityList<int, NetworkTcpSession>(200);
            this.networkTcpSessionList.PopularityLost+=new PopularityList<int, NetworkTcpSession>.PopularityLostEventHandler(networkTcpSessionList_PopularityLost);
            this.fileStreamAssemblerList = new FileTransfer.FileStreamAssemblerList(this, 100, this.outputDirectory + PacketParser.FileTransfer.FileStreamAssembler.ASSMEBLED_FILES_DIRECTORY + System.IO.Path.DirectorySeparatorChar);
            this.reconstructedFileList=new List<FileTransfer.ReconstructedFile>();
            this.credentialList=new SortedList<string, NetworkCredential>();
            //this.pendingSessionCredentialList=new SortedList<string, NetworkCredential>();

            this.nonIpPacketHandlerList=new List<PacketHandlers.IPacketHandler>();
            this.packetHandlerList=new List<PacketHandlers.IPacketHandler>();
            this.tcpSessionPacketHandlerList=new List<PacketHandlers.ITcpSessionPacketHandler>();
            //packet handlers should be entered into the handlerList in the order that packets should be processed
            this.nonIpPacketHandlerList.Add(new PacketHandlers.HpSwitchProtocolPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.DnsPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.TftpPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.NetBiosDatagramServicePacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.NetBiosNameServicePacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.UpnpPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.DhcpPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.SipPacketHandler(this));
            this.packetHandlerList.Add(new PacketHandlers.SyslogPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.FtpPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.HttpPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.ImapPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.IrcPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.NetBiosSessionServicePacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.NtlmSspPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.Pop3PacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.SmbCommandPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.Smb2PacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.SmtpPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.SocksPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.SpotifyKeyExchangePacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.SshPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.TabularDataStreamPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.TlsRecordPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.OscarFileTransferPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.OscarPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.IEC_104_PacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.ModbusTcpPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.RdpPacketHandler(this));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.GenericShimPacketHandler<Packets.OpenFlowPacket>(this, ApplicationLayerProtocol.OpenFlow));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.GenericShimPacketHandler<Packets.TpktPacket>(this, ApplicationLayerProtocol.Tpkt));
            this.tcpSessionPacketHandlerList.Add(new PacketHandlers.UnusedTcpSessionProtocolsHandler(this));//this one is needed in order to release packets from the TCP reassembly if they are complete.

            this.keywordList=new byte[0][];
        }

        public System.Threading.AutoResetEvent SetFramesToParseSignalThreshold(int threshold) {
            this.framesToParseThresholdSignaller = new Utils.QueueThresholdSignaller<Frame>(this.framesToParseQueue, threshold);
            return this.framesToParseThresholdSignaller.BelowThresholdEvent;
        }

        void networkTcpSessionList_PopularityLost(int key, NetworkTcpSession value) {
            value.Close();
        }


        public void StartBackgroundThreads() {
            
            //packetHandlerThread.Start();

            this.packetQueueConsumerThread.Start();
            this.frameQueueConsumerThread.Start();
        }

        public void AbortBackgroundThreads() {
            this.packetQueueConsumerThread.Abort();
            this.frameQueueConsumerThread.Abort();
        }

        internal virtual void OnInsufficientWritePermissionsDetected(string path) {
            this.OnAnomalyDetected("User does not have write permissions to " + path);
            if (this.InsufficientWritePermissionsDetected != null) {
                lock (this.insufficientWritePermissionsLock) {
                    this.InsufficientWritePermissionsDetected?.Invoke(path);
                    this.InsufficientWritePermissionsDetected = null;
                }
            }
        }

        // http://msdn.microsoft.com/en-us/library/aa645739(VS.71).aspx
        public virtual void OnAnomalyDetected(Events.AnomalyEventArgs ae) {
            AnomalyDetected?.Invoke(this, ae);
        }
        internal virtual void OnAnomalyDetected(string anomalyMessage) {
            OnAnomalyDetected(anomalyMessage, DateTime.Now);
        }
        internal virtual void OnAnomalyDetected(string anomalyMessage, DateTime anomalyTimestamp) {
            this.OnAnomalyDetected(new Events.AnomalyEventArgs(anomalyMessage, anomalyTimestamp));
        }
        internal virtual void OnParametersDetected(Events.ParametersEventArgs pe) {
            ParametersDetected?.Invoke(this, pe);
        }
        internal virtual void OnNetworkHostDetected(Events.NetworkHostEventArgs he) {
            NetworkHostDetected?.Invoke(this, he);
        }
        public virtual void OnHttpClientDetected(Events.HttpClientEventArgs he) {
            HttpTransactionDetected?.Invoke(this, he);
        }
        internal virtual void OnDnsRecordDetected(Events.DnsRecordEventArgs de) {
            DnsRecordDetected?.Invoke(this, de);
        }
        internal virtual void OnBufferUsageChanged(Events.BufferUsageEventArgs be) {
            BufferUsageChanged?.Invoke(this, be);
        }
        internal virtual void OnFrameDetected(Events.FrameEventArgs fe) {
            FrameDetected?.Invoke(this, fe);
        }
        internal virtual void OnCleartextWordsDetected(Events.CleartextWordsEventArgs ce) {
            CleartextWordsDetected?.Invoke(this, ce);
        }
        internal virtual void OnFileReconstructed(Events.FileEventArgs fe) {
            FileReconstructed?.Invoke(this, fe);
        }
        internal virtual void OnKeywordDetected(Events.KeywordEventArgs ke) {
            KeywordDetected?.Invoke(this, ke);
        }

        //this one should only be called by PacketParser.PachetHandler so that credentials can be filtered later on
        private void OnCredentialDetected(Events.CredentialEventArgs ce) {
            CredentialDetected?.Invoke(this, ce);
        }
        internal virtual void OnSessionDetected(Events.SessionEventArgs se) {
            this.SessionDetected?.Invoke(this, se);
        }


        internal virtual void OnMessageDetected(Events.MessageEventArgs me) {
            this.MessageDetected?.Invoke(this, me);
        }
        internal virtual void OnMessageAttachmentDetected(string messageId, PacketParser.FileTransfer.ReconstructedFile file) {
            this.MessageAttachmentDetected?.Invoke(messageId, file);
        }

        private IEnumerable<string> GetCleartextWords(Packets.AbstractPacket packet) {
            return GetCleartextWords(packet.ParentFrame.Data, packet.PacketStartIndex, packet.PacketEndIndex);
        }
        private IEnumerable<string> GetCleartextWords(byte[] data) {
            return GetCleartextWords(data, 0, data.Length-1);
        }
        /// <summary>
        /// Displays words in cleartext that exists in the provided data range
        /// </summary>
        /// <param name="data">Array of data</param>
        /// <param name="startIndex">Index in array to start search at</param>
        /// <param name="endIndex">Index in array to en search in</param>
        /// <returns></returns>
        private IEnumerable<string> GetCleartextWords(byte[] data, int startIndex, int endIndex) {
            if (this.dictionary.WordCount > 0) {
                StringBuilder sb = null;//new StringBuilder();
                for (int i = startIndex; i <= endIndex; i++) {
                    if (dictionary.IsLetter(data[i])) {
                        if (sb == null)
                            sb = new StringBuilder(Convert.ToString((char)data[i]));
                        else
                            sb.Append((char)data[i]);
                    }
                    else {
                        if (sb != null) {
                            if (dictionary.HasWord(sb.ToString()))
                                yield return sb.ToString();
                            sb = null;
                        }
                    }
                }
                if (sb != null && dictionary.HasWord(sb.ToString()))
                    yield return sb.ToString();
            }
        }


        /// <summary>
        /// Callback method to receive packets from a sniffer
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="packet"></param>
        public bool TryEnqueueReceivedPacket(object sender, NetworkWrapper.PacketReceivedEventArgs packet) {
            if(this.receivedPacketsQueue.Count<RECEIVED_PACKETS_QUEUE_MAX_SIZE) {
                lock (this.receivedPacketsQueue)
                    this.receivedPacketsQueue.Enqueue(packet);
                //this.receivedPacketsQueueEvent.Set();

                this.OnBufferUsageChanged(new Events.BufferUsageEventArgs((this.receivedPacketsQueue.Count*100)/RECEIVED_PACKETS_QUEUE_MAX_SIZE));
                //this.parentForm.SetBufferUsagePercent((this.receivedPacketsQueue.Count*100)/RECEIVED_PACKETS_QUEUE_MAX_SIZE);
                return true;
            }
            else {
                this.OnAnomalyDetected("Packet dropped");
                //this.parentForm.ShowError("Packet dropped");
                return false;
            }
        }

        private void UpdateBufferUsagePercent() {
            int usage=Math.Max(this.receivedPacketsQueue.Count, this.framesToParseQueue.Count/2);
            int percent=(usage*100)/RECEIVED_PACKETS_QUEUE_MAX_SIZE;
            if(lastBufferUsagePercent==null || percent!=lastBufferUsagePercent.Value) {
                lastBufferUsagePercent=percent;
                this.OnBufferUsageChanged(new Events.BufferUsageEventArgs((usage*100)/RECEIVED_PACKETS_QUEUE_MAX_SIZE));
            }
        }


        internal void CreateFramesFromPacketsInPacketQueue(){
            try {
                while (true) {
                    if (this.receivedPacketsQueue.Count > 0 && this.framesToParseQueue.Count < RECEIVED_PACKETS_QUEUE_MAX_SIZE) {
                        NetworkWrapper.PacketReceivedEventArgs packet;
                        lock (receivedPacketsQueue)
                            packet = receivedPacketsQueue.Dequeue();
                        UpdateBufferUsagePercent();
                        Frame frame = this.GetFrame(packet);
                        //this.ParseFrame(frame);
                        AddFrameToFrameParsingQueue(frame);
                    }
                    else {
                        //this.nFramesReceived
                        System.Threading.Thread.Sleep(50);
                        //this.receivedPacketsQueueEvent.WaitOne(1000);//one second timeout
                    }
                }
            }
            catch(System.Threading.ThreadAbortException) {
                throw;
            }
#if !DEBUG
            catch(Exception e) {
                if (this.UnhandledException == null)
                    throw e;
                else
                    this.UnhandledException(AppDomain.CurrentDomain, new UnhandledExceptionEventArgs(e, true));
            }
#endif
        }


        public void AddFrameToFrameParsingQueue(Frame frame) {
            if(frame!=null) {
                lock(this.framesToParseQueue)
                    this.framesToParseQueue.Enqueue(frame);
                //this.framesToParseQueueEvent.Set();
                //this.nFramesReceived++;

            }
        }
        internal void ParseFramesInFrameQueue() {
            try {
                while (true) {
                    int framesToParseCount = this.framesToParseQueue.Count;
                    if (this.framesToParseQueue.Count > 0) {
                        Frame f;
                        lock (this.framesToParseQueue)
                            f = framesToParseQueue.Dequeue();
                        UpdateBufferUsagePercent();
                        this.ParseFrame(f);
                        this.framesToParseThresholdSignaller?.SignalIfBelowThreshold();
                    }
                    else {

                        System.Threading.Thread.Sleep(50);
                        //this.framesToParseQueueEvent.WaitOne(1000);
                    }
                }
            }
            catch (System.Threading.ThreadAbortException) {
                throw;
            }
#if !DEBUG
            catch (Exception e) {
                if (this.UnhandledException == null)
                    throw e;
                else
                    this.UnhandledException(AppDomain.CurrentDomain, new UnhandledExceptionEventArgs(e, true));
            }
#endif
        }


        public Frame GetFrame(DateTime timestamp, byte[] data, PcapFileHandler.PcapFrame.DataLinkTypeEnum dataLinkType) {
            //NetworkWrapper.PacketReceivedEventArgs.PacketTypes fileDataLinkType=NetworkWrapper.PacketReceivedEventArgs.PacketTypes.Ethernet2Packet;//I'll let this be the default base packet to parse


            /*
            Type packetType=typeof(Packets.Ethernet2Packet);//use Ethernet as default
            //let's see if hte data link packet type is something else than ethernet...
            //is it maybe 802.11 (W-LAN)?
            if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_IEEE_802_11 || dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_IEEE_802_11_WLAN_AVS) {
                packetType=typeof(Packets.IEEE_802_11Packet);
            }
            //802.11 after a RadioTap header
            else if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_IEEE_802_11_WLAN_RADIOTAP) {
                packetType=typeof(Packets.IEEE_802_11RadiotapPacket);
            }
            //Or raw IP?
            else if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_RAW_IP ||
                            dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_RAW_IP_2 ||
                            dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_RAW_IP_3) {
                packetType=typeof(Packets.IPv4Packet);
            }
            else if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_CHDLC) {
                packetType=typeof(Packets.CiscoHdlcPacket);
            }
            else if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_SLL) {
                packetType=typeof(Packets.LinuxCookedCapture);
            }
            else if(dataLinkType==PcapFileHandler.PcapFileReader.DataLinkType.WTAP_ENCAP_PRISM_HEADER) {
                packetType=typeof(Packets.PrismCaptureHeaderPacket);
            }*/

            Type packetType = Packets.PacketFactory.GetPacketType(dataLinkType);

            return new Frame(timestamp, data, packetType, ++nFramesReceived);
        }

        internal Frame GetFrame(NetworkWrapper.PacketReceivedEventArgs packet) {
            //Frame receivedFrame=null;

            if (packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.Ethernet2Packet) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.Ethernet2Packet), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.IPv4Packet) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.IPv4Packet), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.IPv6Packet) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.IPv6Packet), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.IEEE_802_11Packet) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.IEEE_802_11Packet), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.IEEE_802_11RadiotapPacket) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.IEEE_802_11RadiotapPacket), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.CiscoHDLC) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.CiscoHdlcPacket), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.LinuxCookedCapture) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.LinuxCookedCapture), ++nFramesReceived);
            }
            else if(packet.PacketType==NetworkWrapper.PacketReceivedEventArgs.PacketTypes.PrismCaptureHeader) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.PrismCaptureHeaderPacket), ++nFramesReceived);
            }
            else if (packet.PacketType == NetworkWrapper.PacketReceivedEventArgs.PacketTypes.NullLoopback) {
                return new Frame(packet.Timestamp, packet.Data, typeof(Packets.NullLoopbackPacket), ++nFramesReceived);
            }
            else
                return null;
            //ParseFrame(receivedFrame);
        }

        private bool FilterMatches(Packets.IPv4Packet ipv4Packet, Packets.IPv6Packet ipv6Packet, Packets.TcpPacket tcpPacket, Packets.UdpPacket udpPacket) {
            if (this.inputFilter == null)
                return true;

            string transportProtocol;
            ushort srcPort, dstPort;
            if (tcpPacket != null) {
                transportProtocol = "TCP";
                srcPort = tcpPacket.SourcePort;
                dstPort = tcpPacket.DestinationPort;
            }
            else if (udpPacket != null) {
                transportProtocol = "UDP";
                srcPort = udpPacket.SourcePort;
                dstPort = udpPacket.DestinationPort;
            }
            else
                return false;

            if (ipv4Packet != null) {
                return this.inputFilter.Matches(new IPEndPoint(ipv4Packet.SourceIPAddress, srcPort), new IPEndPoint(ipv4Packet.DestinationIPAddress, dstPort), transportProtocol);
            }
            else if (ipv6Packet != null) {
                return this.inputFilter.Matches(new IPEndPoint(ipv6Packet.SourceIPAddress, srcPort), new IPEndPoint(ipv6Packet.DestinationIPAddress, dstPort), transportProtocol);
            }
            else
                return false;
        }

        internal void ParseFrame(Frame receivedFrame){
            
            if(receivedFrame!=null) {
                

                this.nBytesReceived+=receivedFrame.Data.Length;

                //receivedFramesQueue.Enqueue(receivedFrame);

                Packets.Ethernet2Packet ethernet2Packet=null;
                Packets.IEEE_802_11Packet WlanPacket=null;
                Packets.ArpPacket arpPacket=null;
                Packets.IPv4Packet ipv4Packet=null;
                Packets.IPv6Packet ipv6Packet=null;
                Packets.TcpPacket tcpPacket=null;
                Packets.UdpPacket udpPacket=null;
                Packets.RawPacket rawPacket=null;
                List<ushort> vlanIdList = new List<ushort>();

                foreach(Packets.AbstractPacket p in receivedFrame.PacketList) {
                    if (p.GetType() == typeof(Packets.IPv4Packet))
                        ipv4Packet = (Packets.IPv4Packet)p;
                    else if (p.GetType() == typeof(Packets.IPv6Packet))
                        ipv6Packet = (Packets.IPv6Packet)p;
                    else if (p.GetType() == typeof(Packets.TcpPacket))
                        tcpPacket = (Packets.TcpPacket)p;
                    else if (p.GetType() == typeof(Packets.UdpPacket))
                        udpPacket = (Packets.UdpPacket)p;
                    else if (p.GetType() == typeof(Packets.Ethernet2Packet))
                        ethernet2Packet = (Packets.Ethernet2Packet)p;
                    else if (p.GetType() == typeof(Packets.IEEE_802_11Packet))
                        WlanPacket = (Packets.IEEE_802_11Packet)p;
                    else if (p.GetType() == typeof(Packets.ArpPacket))
                        arpPacket = (Packets.ArpPacket)p;
                    else if (p.GetType() == typeof(Packets.RawPacket))
                        rawPacket = (Packets.RawPacket)p;
                    else if (p.GetType() == typeof(Packets.IEEE_802_1Q_VlanPacket)) {
                        ushort vlanId = ((Packets.IEEE_802_1Q_VlanPacket)p).VlanID;
                        if (!vlanIdList.Contains(vlanId))
                            vlanIdList.Add(vlanId);
                    }
                }

                if (this.FilterMatches(ipv4Packet, ipv6Packet, tcpPacket, udpPacket)) {

                    this.OnFrameDetected(new Events.FrameEventArgs(receivedFrame));
                    if (ethernet2Packet != null && arpPacket != null) {
                        //this must be done also for IEEE 802.11 !!!
                        ExtractArpData(ethernet2Packet, arpPacket);
                    }


                    NetworkPacket networkPacket = null;
                    if (ipv4Packet == null && ipv6Packet == null) {
                        foreach (PacketHandlers.IPacketHandler packetHandler in nonIpPacketHandlerList) {
                            try {
                                NetworkHost sourceHost = new NetworkHost(IPAddress.None);
                                packetHandler.ExtractData(ref sourceHost, null, receivedFrame.PacketList/*.Values*/);
                            }
                            catch (Exception ex) {
                                this.OnAnomalyDetected("Error applying " + packetHandler.ToString() + " packet handler to frame " + receivedFrame.ToString() + ": " + ex.Message, receivedFrame.Timestamp);
                            }
                        }

                    }
                    else if (ipv4Packet != null || ipv6Packet != null) {
                        byte ipTTL;
                        IPAddress ipPacketSourceIp;
                        IPAddress ipPacketDestinationIp;
                        Packets.AbstractPacket ipPacket;
                        if (ipv6Packet != null) {
                            ipTTL = ipv6Packet.HopLimit;
                            ipPacketSourceIp = ipv6Packet.SourceIPAddress;
                            ipPacketDestinationIp = ipv6Packet.DestinationIPAddress;
                            ipPacket = ipv6Packet;
                        }
                        else {//if(ipv4Packet!=null) {
                            ipTTL = ipv4Packet.TimeToLive;
                            ipPacketSourceIp = ipv4Packet.SourceIPAddress;
                            ipPacketDestinationIp = ipv4Packet.DestinationIPAddress;
                            ipPacket = ipv4Packet;
                        }

                        NetworkHost sourceHost, destinationHost;
                        //source
                        if (networkHostList.ContainsIP(ipPacketSourceIp))
                            sourceHost = networkHostList.GetNetworkHost(ipPacketSourceIp);
                        else {
                            sourceHost = new NetworkHost(ipPacketSourceIp);
                            lock(this.networkHostList)
                                this.networkHostList.Add(sourceHost);
                            this.OnNetworkHostDetected(new Events.NetworkHostEventArgs(sourceHost));
                            //parentForm.ShowDetectedHost(sourceHost);
                        }
                        if (networkHostList.ContainsIP(ipPacketDestinationIp))
                            destinationHost = networkHostList.GetNetworkHost(ipPacketDestinationIp);
                        else {
                            destinationHost = new NetworkHost(ipPacketDestinationIp);
                            lock (this.networkHostList)
                                this.networkHostList.Add(destinationHost);
                            this.OnNetworkHostDetected(new Events.NetworkHostEventArgs(destinationHost));
                            //parentForm.ShowDetectedHost(destinationHost);
                        }
                        //we now have sourceHost and destinationHost
                        networkPacket = new NetworkPacket(sourceHost, destinationHost, ipPacket);

                        if (ethernet2Packet != null) {
                            if (sourceHost.MacAddress != ethernet2Packet.SourceMACAddress) {
                                if (sourceHost.MacAddress != null && ethernet2Packet.SourceMACAddress != null && sourceHost.MacAddress.ToString() != ethernet2Packet.SourceMACAddress.ToString())
                                    if (!sourceHost.IsRecentMacAddress(ethernet2Packet.SourceMACAddress) && !sourceHost.IPAddress.Equals(IPAddress.Parse("0.0.0.0")))
                                        this.OnAnomalyDetected("Ethernet MAC has changed, possible ARP spoofing! IP " + sourceHost.IPAddress.ToString() + ", MAC " + sourceHost.MacAddress.ToString() + " -> " + ethernet2Packet.SourceMACAddress.ToString() + " (frame " + receivedFrame.FrameNumber + ")", receivedFrame.Timestamp);
                                sourceHost.MacAddress = ethernet2Packet.SourceMACAddress;
                            }
                            if (destinationHost.MacAddress != ethernet2Packet.DestinationMACAddress) {
                                if (destinationHost.MacAddress != null && ethernet2Packet.DestinationMACAddress != null && destinationHost.MacAddress.ToString() != ethernet2Packet.DestinationMACAddress.ToString())
                                    if (!destinationHost.IsRecentMacAddress(ethernet2Packet.DestinationMACAddress) && !destinationHost.IPAddress.Equals(IPAddress.Parse("0.0.0.0")))
                                        this.OnAnomalyDetected("Ethernet MAC has changed, possible ARP spoofing! IP " + destinationHost.IPAddress.ToString() + ", MAC " + destinationHost.MacAddress.ToString() + " -> " + ethernet2Packet.DestinationMACAddress.ToString() + " (frame " + receivedFrame.FrameNumber + ")", receivedFrame.Timestamp);
                                destinationHost.MacAddress = ethernet2Packet.DestinationMACAddress;
                            }
                        }
                        else if (WlanPacket != null) {
                            sourceHost.MacAddress = WlanPacket.SourceMAC;
                            destinationHost.MacAddress = WlanPacket.DestinationMAC;
                        }

                        /*OS Fingerprinting code used to be here, but has been moved further down in order to be after the PacketHandlers*/
                        //this one checks for OS's in all sorts of packets (for example TCP SYN or DHCP Request)

                        FiveTuple fiveTuple = null;

                        if (tcpPacket != null) {
                            networkPacket.SetTcpData(tcpPacket);

                            NetworkTcpSession networkTcpSession = GetNetworkTcpSession(tcpPacket, sourceHost, destinationHost);

                            if (networkTcpSession != null) {
                                //add packet to session
                                if (!networkTcpSession.TryAddPacket(tcpPacket, sourceHost, destinationHost))
                                    networkTcpSession = null;//the packet did apparently not belong to the TCP session
                                else
                                    fiveTuple = networkTcpSession.Flow.FiveTuple;

                            }





                            if (networkTcpSession != null) {
                                ExtractTcpSessionData(sourceHost, destinationHost, networkTcpSession, receivedFrame, tcpPacket);
                            }

                        }//end TCP packet
                        else if (udpPacket != null) {
                            networkPacket.SetUdpData(udpPacket);
                        }

                        foreach(ushort vlanID in vlanIdList) { 
                            sourceHost.AddVlanID(vlanID);
                            destinationHost.AddVlanID(vlanID);
                        }
                        sourceHost.AddTtl(ipTTL);

                        //this one is just extra for hosts which don't use TCP for example and therefore can't use the OS fingerprinter to get the TTL distance
                        if (sourceHost.TtlDistance == byte.MaxValue) {//maxValue=default if no TtlDistance exists
                            foreach (Fingerprints.IOsFingerprinter fingerprinter in this.osFingerprintCollectionList)
                                if (typeof(Fingerprints.ITtlDistanceCalculator).IsAssignableFrom(fingerprinter.GetType()))
                                    //if(fingerprinter.GetType().IsSubclassOf(typeof(Fingerprints.ITtlDistanceCalculator)))
                                    sourceHost.AddProbableTtlDistance(((Fingerprints.ITtlDistanceCalculator)fingerprinter).GetTtlDistance(ipTTL));
                            //sourceHost.AddProbableTtlDistance(fingerprinter.GetTtlDistance(ipv4Packet.TimeToLive));
                        }


                        //Iterate through all PacketHandlers for packets not inside a TCP stream
                        //It can also be the case that the packet can be either inside TCP or inside UDP (such as the NetBiosNameServicePacket)
                        //All packets here must however always be complete in each frame (i.e. no TCP reassembly is being done)
                        foreach (PacketHandlers.IPacketHandler packetHandler in packetHandlerList) {
                            try {
                                packetHandler.ExtractData(ref sourceHost, destinationHost, receivedFrame.PacketList);
                            }
                            catch (Exception ex) {
                                this.OnAnomalyDetected("Error applying " + packetHandler.ToString() + " packet handler to frame " + receivedFrame.ToString() + ": " + ex.Message, receivedFrame.Timestamp);
                            }
                        }

                        foreach (Fingerprints.IOsFingerprinter fingerprinter in this.osFingerprintCollectionList) {
                            //IList<string> osList;
                            IList<PacketParser.Fingerprints.DeviceFingerprint> osList;
                            if (fingerprinter.TryGetOperatingSystems(out osList, receivedFrame.PacketList/*.Values*/)) {
                                if (osList != null && osList.Count > 0) {
                                    foreach (PacketParser.Fingerprints.DeviceFingerprint os in osList) {
                                        //sourceHost.AddProbableOs(fingerprinter.Name, os, fingerprinter.Confidence/osList.Count);
                                        sourceHost.AddProbableOs(os.ToString(), fingerprinter, 1.0 / osList.Count);
                                        if (os.Category != null && os.Category.Length > 0)
                                            sourceHost.AddProbableDeviceCategory(os.Category, fingerprinter, 1.0 / osList.Count);
                                        if (os.Family != null && os.Family.Length > 0)
                                            sourceHost.AddProbableDeviceFamily(os.Family, fingerprinter, 1.0 / osList.Count);
                                    }
                                    if (typeof(Fingerprints.ITtlDistanceCalculator).IsAssignableFrom(fingerprinter.GetType())) {
                                        //if(fingerprinter.GetType().IsSubclassOf(typeof(Fingerprints.ITtlDistanceCalculator))) {
                                        byte ttlDistance;
                                        if (((Fingerprints.ITtlDistanceCalculator)fingerprinter).TryGetTtlDistance(out ttlDistance, receivedFrame.PacketList/*.Values*/))
                                            sourceHost.AddProbableTtlDistance(ttlDistance);
                                    }
                                }
                            }
                        }


                    }//end of IP packet if clause


                    if (networkPacket != null) {
                        networkPacket.SourceHost.SentPackets.Add(networkPacket);
                        networkPacket.DestinationHost.ReceivedPackets.Add(networkPacket);
                    }

                    //check the frame content for cleartext
                    CheckFrameCleartext(receivedFrame);

                    //check the frame content for keywords
                    foreach (byte[] keyword in this.keywordList) {
                        //jAG SLUTADE HÄR. FUNKAR EJ VID RELOAD
                        int keyIndex = receivedFrame.IndexOf(keyword);
                        if (keyIndex >= 0) {
                            if (networkPacket != null)
                                if (networkPacket.SourceTcpPort != null && networkPacket.DestinationTcpPort != null)
                                    this.OnKeywordDetected(new Events.KeywordEventArgs(receivedFrame, keyIndex, keyword.Length, networkPacket.SourceHost, networkPacket.DestinationHost, "TCP " + networkPacket.SourceTcpPort.ToString(), "TCP " + networkPacket.DestinationTcpPort.ToString()));
                                //this.parentForm.AddDetectedKeyword(receivedFrame, keyIndex, keyword.Length, networkPacket.SourceHost, networkPacket.DestinationHost, "TCP "+networkPacket.SourceTcpPort.ToString(), "TCP "+networkPacket.DestinationTcpPort.ToString());
                                else if (networkPacket.SourceUdpPort != null && networkPacket.DestinationUdpPort != null)
                                    this.OnKeywordDetected(new Events.KeywordEventArgs(receivedFrame, keyIndex, keyword.Length, networkPacket.SourceHost, networkPacket.DestinationHost, "UDP " + networkPacket.SourceUdpPort.ToString(), "UDP " + networkPacket.DestinationUdpPort.ToString()));
                                else
                                    this.OnKeywordDetected(new Events.KeywordEventArgs(receivedFrame, keyIndex, keyword.Length, networkPacket.SourceHost, networkPacket.DestinationHost, "", ""));
                            else
                                this.OnKeywordDetected(new Events.KeywordEventArgs(receivedFrame, keyIndex, keyword.Length, null, null, "", ""));


                        }
                    }
                }//end of filter if clause

            }//end of receivedFrame

        }



        private void ExtractTcpSessionData(NetworkHost sourceHost, NetworkHost destinationHost, NetworkTcpSession networkTcpSession, Frame receivedFrame, Packets.TcpPacket tcpPacket) {
            NetworkTcpSession.TcpDataStream currentStream=null;
            bool transferIsClientToServer;
            if (networkTcpSession.ClientHost == sourceHost && networkTcpSession.ClientTcpPort == tcpPacket.SourcePort) {
                currentStream = networkTcpSession.ClientToServerTcpDataStream;
                transferIsClientToServer = true;
            }
            else if (networkTcpSession.ServerHost == sourceHost && networkTcpSession.ServerTcpPort == tcpPacket.SourcePort) {
                currentStream = networkTcpSession.ServerToClientTcpDataStream;
                transferIsClientToServer = false;
            }
            else
                throw new Exception("Wrong TCP Session received");


            if (currentStream != null && tcpPacket.PayloadDataLength > 0) {
                //0: Check the number of sequenced packets!
                NetworkTcpSession.TcpDataStream.VirtualTcpData virtualTcpData=currentStream.GetNextVirtualTcpData();

                while(virtualTcpData!=null && currentStream.CountBytesToRead()>0) {
                    //1: check if there is an active file stream assembly going on...
                    //   if yes: add the virtualTcpData to the stream
                    if(fileStreamAssemblerList.ContainsAssembler(networkTcpSession.Flow.FiveTuple, transferIsClientToServer, true)) {
                        //this could be any type of TCP packet... but probably part of a file transfer...
                        FileTransfer.FileStreamAssembler assembler=fileStreamAssemblerList.GetAssembler(networkTcpSession.Flow.FiveTuple, transferIsClientToServer);
                        //HTTP 1.0 (but sometimes 1.1) sends a FIN flag when the last packet of a file is sent
                        //See: http://www.mail-archive.com/wireshark-dev@wireshark.org/msg08695.html
                        //This is also useful for FTP data transfers
                        if(assembler.FileContentLength==-1 && assembler.FileSegmentRemainingBytes==-1 && tcpPacket.FlagBits.Fin) {//the last packet of the file
                            assembler.SetRemainingBytesInFile(virtualTcpData.GetBytes(false).Length);
                            assembler.FileSegmentRemainingBytes=virtualTcpData.GetBytes(false).Length;
                        }
                        if (assembler.FileStreamType == FileTransfer.FileStreamTypes.HttpGetChunked || assembler.FileStreamType == FileTransfer.FileStreamTypes.HttpPostMimeMultipartFormData || assembler.FileStreamType == FileTransfer.FileStreamTypes.OscarFileTransfer || assembler.FileSegmentRemainingBytes >= virtualTcpData.ByteCount || (assembler.FileContentLength == -1 && assembler.FileSegmentRemainingBytes == -1)) {
                            assembler.AddData(virtualTcpData.GetBytes(false), virtualTcpData.FirstPacketSequenceNumber);
                            currentStream.RemoveData(virtualTcpData);
                        }
                        else if (assembler.FileSegmentRemainingBytes > 0 && assembler.FileSegmentRemainingBytes < virtualTcpData.ByteCount && assembler.FileStreamType == FileTransfer.FileStreamTypes.HttpGetNormal) {//I would love to add some more FileStreamTypes here!
                            byte[] allBytes = virtualTcpData.GetBytes(false);
                            byte[] trimmedBytes = new byte[assembler.FileSegmentRemainingBytes];
                            Array.Copy(allBytes, trimmedBytes, trimmedBytes.Length);
                            assembler.AddData(trimmedBytes, virtualTcpData.FirstPacketSequenceNumber);
                            currentStream.RemoveData(trimmedBytes.Length);
                        }
                        else {
                            //regardless if I could use the data or not I will now remove it from the stream since the data is already in the assembler now
                            currentStream.RemoveData(virtualTcpData);
                        }
                    }

                    //2: if no file stream: try to reassemble a sub-TCP packet
                    //   if yes: parse it
                    else if (networkTcpSession.RequiredNextTcpDataStream == null || networkTcpSession.RequiredNextTcpDataStream == currentStream) {
                        if (networkTcpSession.RequiredNextTcpDataStream != null)
                            networkTcpSession.RequiredNextTcpDataStream = null; //reset next packet source, only used at the start of stream
                        byte[] virtualTcpBytes = virtualTcpData.GetBytes(true);
                        Frame virtualFrame = new Frame(receivedFrame.Timestamp, virtualTcpBytes, typeof(Packets.TcpPacket), receivedFrame.FrameNumber, false, false, virtualTcpBytes.Length);

                        List<Packets.AbstractPacket> packetList = new List<PacketParser.Packets.AbstractPacket>();
                        try {
                            if (virtualFrame.BasePacket != null)
                                packetList.AddRange(((Packets.TcpPacket)virtualFrame.BasePacket).GetSubPackets(true, networkTcpSession.ProtocolFinder, currentStream == networkTcpSession.ClientToServerTcpDataStream));

                            int parsedBytes = 0;
                            foreach (PacketHandlers.ITcpSessionPacketHandler packetHandler in tcpSessionPacketHandlerList) {
                                parsedBytes += packetHandler.ExtractData(networkTcpSession, transferIsClientToServer, packetList);
                            }
                            if (parsedBytes >= virtualTcpData.ByteCount)
                                networkTcpSession.RemoveData(virtualTcpData, sourceHost, tcpPacket.SourcePort);
                            else if (parsedBytes > 0)
                                networkTcpSession.RemoveData(virtualTcpData.FirstPacketSequenceNumber, parsedBytes, sourceHost, tcpPacket.SourcePort);
                        }
                        catch (Exception e) {
                            this.OnAnomalyDetected(new Events.AnomalyEventArgs("Error parsing TCP contents of frame " + tcpPacket.ParentFrame.FrameNumber + " (src "+ tcpPacket.SourcePort +", dst "+tcpPacket.DestinationPort+") : " + e.ToString(), tcpPacket.ParentFrame.Timestamp));
                        }

                    }

                    //   if no: try to read more packets to the virtyalTcpData
                    virtualTcpData=currentStream.GetNextVirtualTcpData();
                }



            }
            else{
                //we now have a tcpPacket without a payload. Probably a SYN, ACK or other control packet

                //some packets (such as FTP) need to see new upcoming TCP sessions since they identify/activate file transfer sessions that way
                foreach(PacketHandlers.ITcpSessionPacketHandler packetHandler in tcpSessionPacketHandlerList)
                    packetHandler.ExtractData(networkTcpSession, transferIsClientToServer, receivedFrame.PacketList/*.Values*/);
                    //skip the return value, it isn't needed here
            }
            if(networkTcpSession.FinPacketReceived || networkTcpSession.SessionClosed) {

                //see if there is a file stream assembler and close it
                this.closeAssemblerIfExists(networkTcpSession.Flow.FiveTuple, true);
                //this.closeAssemblerIfExists(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, FiveTuple.TransportProtocol.TCP, true);
                //close assembler in opposite direction as well
                //this.closeAssemblerIfExists(destinationHost, tcpPacket.DestinationPort, sourceHost, tcpPacket.SourcePort, FiveTuple.TransportProtocol.TCP, true);
                this.closeAssemblerIfExists(networkTcpSession.Flow.FiveTuple, false);
                /*

                if(fileStreamAssemblerList.ContainsAssembler(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, true, true)) {
                    //we have an assembler, let's close it
                    using(FileTransfer.FileStreamAssembler assembler=fileStreamAssemblerList.GetAssembler(sourceHost, tcpPacket.SourcePort, destinationHost, tcpPacket.DestinationPort, true)) {
                        if(assembler.IsActive && assembler.FileSegmentRemainingBytes<=0 && assembler.AssembledByteCount>0) {
                            //I'll assume that the file transfer was OK
                            assembler.FinishAssembling();
                        }
                        else {
                            fileStreamAssemblerList.Remove(assembler, true);
                        }
                    }
                }
                */


            }

        }

        private void closeAssemblerIfExists(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, FiveTuple.TransportProtocol transport, bool transferIsClientToServer) {
            FiveTuple tmpFiveTuple = new FiveTuple(sourceHost, sourcePort, destinationHost, destinationPort, transport);
            closeAssemblerIfExists(tmpFiveTuple, transferIsClientToServer);
        }

        private void closeAssemblerIfExists(FiveTuple fiveTuple, bool transferIsClientToServer) { 
            if (fileStreamAssemblerList.ContainsAssembler(fiveTuple, transferIsClientToServer, true)) {
                //we have an assembler, let's close it
                using (FileTransfer.FileStreamAssembler assembler = fileStreamAssemblerList.GetAssembler(fiveTuple, transferIsClientToServer)) {
                    if (assembler.IsActive && assembler.AssembledByteCount > 0 && (assembler.FileSegmentRemainingBytes <= 0 || assembler.ContentRange != null)) {
                        //I'll assume that the file transfer was OK
                        assembler.FinishAssembling();
                    }
                    else {
                        fileStreamAssemblerList.Remove(assembler, true);
                    }
                }
            }
        }

        

        private void AddNetworkTcpSessionToPool(NetworkTcpSession session){
            int sessionHash=session.GetHashCode();
            if(this.networkTcpSessionList.ContainsKey(sessionHash))//earlier session with the same IP's and port numbers
                this.networkTcpSessionList[sessionHash]=session;//replace the old with the new in the dictionary only!
            else
                this.networkTcpSessionList.Add(sessionHash, session);
        }
        private NetworkTcpSession GetNetworkTcpSession(Packets.TcpPacket tcpPacket, NetworkHost sourceHost, NetworkHost destinationHost) {
            if(tcpPacket.FlagBits.Synchronize) {
                if(!tcpPacket.FlagBits.Acknowledgement) {//the first SYN packet
                    NetworkTcpSession session=new NetworkTcpSession(tcpPacket, sourceHost, destinationHost, this.protocolFinderFactory);
                    AddNetworkTcpSessionToPool(session);
                    return session;
                }
                else {//SYN+ACK packet (server -> client)
                    int key=NetworkTcpSession.GetHashCode(destinationHost, sourceHost, tcpPacket.DestinationPort, tcpPacket.SourcePort);

                    if(this.networkTcpSessionList.ContainsKey(key)) {
                        NetworkTcpSession session=networkTcpSessionList[key];
                        if(session.SynPacketReceived && !session.SynAckPacketReceived) {//we now have an established session

                            return session;
                        }
                        else
                            return null;
                    }
                    else//stray SYN+ACK packet
                        return null;
                    
                }
            }
            else {//No SYN packet. There should be an active session

                int clientToServerKey=NetworkTcpSession.GetHashCode(sourceHost, destinationHost, tcpPacket.SourcePort, tcpPacket.DestinationPort);
                int serverToClientKey=NetworkTcpSession.GetHashCode(destinationHost, sourceHost, tcpPacket.DestinationPort, tcpPacket.SourcePort);


                if(this.networkTcpSessionList.ContainsKey(clientToServerKey)) {//see if packet is client to server
                    NetworkTcpSession session=this.networkTcpSessionList[clientToServerKey];
                    if(session.SynAckPacketReceived)
                        return session;
                    else
                        return null;
                }
                else if(this.networkTcpSessionList.ContainsKey(serverToClientKey)) {//see if packet is server to client
                    NetworkTcpSession session=this.networkTcpSessionList[serverToClientKey];
                    if(session.SynAckPacketReceived)
                        return session;
                    else {
                        return null;
                    }
                }
                else {//no such session.... exists. Try to create a new non-complete session
                    NetworkTcpSession session=new NetworkTcpSession(sourceHost, destinationHost, tcpPacket, this.protocolFinderFactory);//create a truncated session
                    AddNetworkTcpSessionToPool(session);
                    return session;
                }
            }
        }


        internal void AddReconstructedFile(FileTransfer.ReconstructedFile file) {
            //let's timestomp the last write time of the file before passing it on
            try {
                System.IO.File.SetLastWriteTime(file.FilePath, file.Timestamp);
            }
            catch (Exception e) {
                this.OnAnomalyDetected("Error timestomping reconstructed file: " + e.Message);
            }

            this.reconstructedFileList.Add(file);
            this.OnFileReconstructed(new Events.FileEventArgs(file));
            //parentForm.ShowReconstructedFile(file);
        }
        internal void AddCredential(NetworkCredential credential) {
            /*
            if(!credentialList.ContainsKey(credential.Key))
                this.credentialList.Add(credential.Key, credential);
            else
                this.credentialList[credential.Key]=credential;
            if(credential.Password!=null)
                parentForm.ShowCredential(credential);
             * */
            if(!credentialList.ContainsKey(credential.Key)) {
                this.credentialList.Add(credential.Key, credential);
                if(credential.Password!=null)
                    this.OnCredentialDetected(new Events.CredentialEventArgs(credential));
                    //parentForm.ShowCredential(credential);
            }          

        }
        public IList<NetworkCredential> GetCredentials() {
            return this.credentialList.Values;
        }


        private void ExtractArpData(Packets.IEEE_802_11Packet wlanPacket, Packets.ArpPacket arpPacket) {
            if(arpPacket.SenderIPAddress!=null && wlanPacket!=null)
                ExtractArpData(wlanPacket.SourceMAC, arpPacket);
        }
        private void ExtractArpData(Packets.Ethernet2Packet ethernet2Packet, Packets.ArpPacket arpPacket) {
            if(arpPacket.SenderIPAddress!=null && ethernet2Packet!=null)
                ExtractArpData(ethernet2Packet.SourceMACAddress, arpPacket);
        }
        private void ExtractArpData(System.Net.NetworkInformation.PhysicalAddress sourceMAC, Packets.ArpPacket arpPacket) {
            if(sourceMAC!=null) {
                if(arpPacket.SenderHardwareAddress.Equals(sourceMAC)) {
                    NetworkHost host=null;
                    if(!this.networkHostList.ContainsIP(arpPacket.SenderIPAddress)) {
                        host=new NetworkHost(arpPacket.SenderIPAddress);
                        host.MacAddress=arpPacket.SenderHardwareAddress;
                        lock(this.networkHostList)
                            this.networkHostList.Add(host);
                        //parentForm.ShowDetectedHost(host);
                        this.OnNetworkHostDetected(new Events.NetworkHostEventArgs(host));
                    }
                    if(host!=null)
                        host.AddQueriedIP(arpPacket.TargetIPAddress);

                }
                else {
                    this.OnAnomalyDetected(
                        "Different source MAC addresses in Ethernet and ARP packet: "+
                                "Ethernet MAC="+sourceMAC+
                                ", ARP MAC="+arpPacket.SenderHardwareAddress+
                                ", ARP IP="+arpPacket.SenderIPAddress+
                                " (frame: "+arpPacket.ParentFrame.ToString()+")", arpPacket.ParentFrame.Timestamp);
                }

            }
        }

        /*
        internal void ExtractMultipartFormData(IEnumerable<Mime.MultipartPart> formMultipartData, FiveTuple fiveTuple, bool transferIsClientToServer, DateTime timestamp, long frameNumber, ApplicationLayerProtocol applicationLayerProtocol) {
            ExtractMultipartFormData(formMultipartData, fiveTuple, transferIsClientToServer sourceHost, destinationHost, timestamp, frameNumber, sourcePort, destinationPort, applicationLayerProtocol, null);
        }
        */
        //internal void ExtractMultipartFormData(IEnumerable<Mime.MultipartPart> formMultipartData, NetworkHost sourceHost, NetworkHost destinationHost, DateTime timestamp, long frameNumber, string sourcePort, string destinationPort, ApplicationLayerProtocol applicationLayerProtocol, System.Collections.Specialized.NameValueCollection cookieParams) {
        internal void ExtractMultipartFormData(IEnumerable<Mime.MultipartPart> formMultipartData, FiveTuple fiveTuple, bool transferIsClientToServer, DateTime timestamp, long frameNumber, ApplicationLayerProtocol applicationLayerProtocol, System.Collections.Specialized.NameValueCollection cookieParams = null) {
            System.Collections.Specialized.NameValueCollection formParameters=new System.Collections.Specialized.NameValueCollection();

            foreach(Mime.MultipartPart part in formMultipartData) {
                if(part.Attributes!=null && part.Attributes.Count>0) {
                    if(part.Data!=null && part.Data.Length>0) {
                        //lookup name and convert multipart data to string
                        string attributeName=part.Attributes["name"];
                        foreach(string key in part.Attributes) {
                            if(key=="name")
                                attributeName=part.Attributes["name"];
                            else
                                formParameters.Add(key, part.Attributes[key]);
                        }

                        int partDataTruncateSize=250;//max 250 characters
                        
                        string partData = Utils.ByteConverter.ReadString(part.Data, 0, partDataTruncateSize).Trim();
                           
                        if(attributeName!=null && attributeName.Length>0) {
                            if(partData!=null && partData.Length>0)
                                formParameters.Add(attributeName, partData);
                            else
                                formParameters.Add("name", attributeName);
                        }
                    }
                    else {
                        formParameters.Add(part.Attributes);
                    }
                }
            }
            if(formParameters.Count>0)
                this.OnParametersDetected(new Events.ParametersEventArgs(frameNumber, fiveTuple, transferIsClientToServer, formParameters, timestamp, "HTTP POST"));
            //check for credentials (usernames and passwords)
            NetworkCredential credential=NetworkCredential.GetNetworkCredential(formParameters, fiveTuple.ClientHost, fiveTuple.ServerHost, "HTTP POST", timestamp);

            if(credential!=null && credential.Username!=null && credential.Password!=null) {
                //mainPacketHandler.AddCredential(new NetworkCredential(sourceHost, destinationHost, "HTTP POST", username, password, httpPacket.ParentFrame.Timestamp));
                this.AddCredential(credential);
            }

            //add cookies if they exist
            if (cookieParams != null)
                foreach (string key in cookieParams.Keys)
                    if (formParameters[key] == null)
                        formParameters[key] = cookieParams[key];

            PacketParser.Events.MessageEventArgs messageEventArgs = GetMessageEventArgs(applicationLayerProtocol, fiveTuple, transferIsClientToServer, frameNumber, timestamp, formParameters);
            if(messageEventArgs!=null)
                this.MessageDetected(this, messageEventArgs);
        }

        private PacketParser.Events.MessageEventArgs GetMessageEventArgs(ApplicationLayerProtocol applicationLayerProtocol, FiveTuple fiveTuple, bool transferIsClientToServer, long frameNumber, DateTime timestamp, System.Collections.Specialized.NameValueCollection parameters) {
            string from = null;
            string to = null;
            string subject = null;
            string message = null;

            string[] fromNames = { "from", "From", "fFrom", "profile_id", "username", "guest_id", "author", "email", "anonName", "rawOpenId"};
            string[] toNames = { "to", "To", "req0_to", "fTo", "ids", "send_to", "emails[0]" };
            string[] subjectNames = { "subject", "Subj", "Subject", "fSubject" };
            string[] messageNames = { "req0_text", "body", "Body", "message", "Message", "text", "Text", "fMessageBody", "status", "PlainBody", "RichBody", "comment", "postBody" };

            /**
             * gmail emails uses "to", "subject" and "body"
             * gmail chat uses "req0_to" and "req0_text"
             * yahoo email uses "To", "Subj" and "Body" {
             * MS Exchange webmail uses "to", "subject" and "message"
             * others might use "from", "to", "subject" and "text"
             * Hotmail use "fFrom", "fTo", "fSubject" and "fMessageBody"
             * Facebook uses "profile_id", "ids", "subject"? and "status"
             * twitter uses "guest_id", ?, "status", "status"
             * AOL email parser uses PlainBody and RichBody
             * Squirrel Mail uses meddelande: username, send_to, subject, body
             * Wordpress uses author + email and comment
             * Blogspot uses anonName + rawOpenId and postBody
             */
            for (int i = 0; i < fromNames.Length && (from == null || from.Length == 0); i++)
                from = parameters[fromNames[i]];
            for(int i=0; i<toNames.Length && (to==null || to.Length == 0); i++)
                to = parameters[toNames[i]];
            for (int i = 0; i < subjectNames.Length && (subject == null || subject.Length == 0); i++)
                subject = parameters[subjectNames[i]];
            for (int i = 0; i < messageNames.Length && (message == null || message.Length == 0); i++)
                message = parameters[messageNames[i]];

            if(subject==null && message!=null && message.Length>0)
                subject=message;
            if (subject != null && subject.Length > 0 && (from != null || to != null)) {
                if(transferIsClientToServer)
                    return new PacketParser.Events.MessageEventArgs(applicationLayerProtocol, fiveTuple.ClientHost, fiveTuple.ServerHost, frameNumber, timestamp, from, to, subject, message, parameters);
                else
                    return new PacketParser.Events.MessageEventArgs(applicationLayerProtocol, fiveTuple.ServerHost, fiveTuple.ClientHost, frameNumber, timestamp, from, to, subject, message, parameters);
            }
            else
                return null;
        }

        private void CheckFrameCleartext(Frame frame) {
            int wordCharCount=0;
            int totalByteCount=0;
            IEnumerable<string> words=null;

            if(this.cleartextSearchModeSelectedIndex==0){//0 = full packet search
                words=GetCleartextWords(frame.Data);
                totalByteCount=frame.Data.Length;
            }
            else if(cleartextSearchModeSelectedIndex==1) {//1 = TCP and UDP payload search
                foreach(Packets.AbstractPacket p in frame.PacketList/*.Values*/) {
                    if(p.GetType()==typeof(Packets.TcpPacket)) {
                        Packets.TcpPacket tcpPacket=(Packets.TcpPacket)p;
                        words=GetCleartextWords(tcpPacket.ParentFrame.Data, tcpPacket.PacketStartIndex+tcpPacket.DataOffsetByteCount, tcpPacket.PacketEndIndex);
                        totalByteCount=tcpPacket.PacketEndIndex-tcpPacket.DataOffsetByteCount-tcpPacket.PacketStartIndex+1;
                    }
                    else if(p.GetType()==typeof(Packets.UdpPacket)) {
                        Packets.UdpPacket udpPacket=(Packets.UdpPacket)p;
                        words=GetCleartextWords(udpPacket.ParentFrame.Data, udpPacket.PacketStartIndex+udpPacket.DataOffsetByteCount, udpPacket.PacketEndIndex);
                        totalByteCount=udpPacket.PacketEndIndex-udpPacket.DataOffsetByteCount-udpPacket.PacketStartIndex+1;
                    }
                }
            }
            else if(cleartextSearchModeSelectedIndex==2) {//2 = raw packet search
                foreach(Packets.AbstractPacket p in frame.PacketList/*.Values*/) {
                    if(p.GetType()==typeof(Packets.RawPacket)){
                        words=GetCleartextWords(p);
                        totalByteCount=p.PacketByteCount;
                    }
                }
            }
            //3 = don't search

            //add data to Form
            if(totalByteCount>0 && words!=null){
                List<string> wordList = new List<string>();
                foreach (string cleartextWord in words) {
                    wordCharCount += cleartextWord.Length;
                    wordList.Add(cleartextWord);
                }
                if (wordList.Count > 0) {
                    OnCleartextWordsDetected(new Events.CleartextWordsEventArgs(wordList, wordCharCount, totalByteCount, frame.FrameNumber, frame.Timestamp));
                    //parentForm.ShowCleartextWords(words, wordCharCount, totalByteCount);
                }
            }
                

        }

    }
}
