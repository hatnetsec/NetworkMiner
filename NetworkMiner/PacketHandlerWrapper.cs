//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Net;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner {

    internal delegate void NewNetworkHostHandler(PacketParser.NetworkHost host);

    public class PacketHandlerWrapper {

        private NetworkMinerForm parentForm;
        private PcapFileHandler.PcapFileWriter pcapWriter;


        private PacketParser.PacketHandler packetHandler;


        public int CleartextSearchModeSelectedIndex { set { this.packetHandler.CleartextSearchModeSelectedIndex=value; } }
        public PacketParser.PacketHandler PacketHandler { get { return this.packetHandler; } }
        public PcapFileHandler.PcapFileWriter PcapWriter { get { return this.pcapWriter; } set { this.pcapWriter=value; } }


        internal PacketHandlerWrapper(NetworkMinerForm parentForm, List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints = null)
            : this(parentForm, new System.IO.DirectoryInfo(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath))), preloadedFingerprints) {
        }

        internal PacketHandlerWrapper(NetworkMinerForm parentForm, System.IO.DirectoryInfo outputDirectory, List<PacketParser.Fingerprints.IOsFingerprinter> preloadedFingerprints) {

            this.parentForm = parentForm;
            this.pcapWriter=null;
            string exePath = System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath);
            this.packetHandler = new PacketParser.PacketHandler(exePath, outputDirectory.FullName, preloadedFingerprints, false);
            

            this.PacketHandler.AnomalyDetected += new PacketParser.AnomalyEventHandler(AnomalyDetected);
            this.PacketHandler.BufferUsageChanged+=new PacketParser.BufferUsageEventHandler(BufferUsageChanged);
            this.packetHandler.CleartextWordsDetected+=new PacketParser.CleartextWordsEventHandler(CleartextWordsDetected);
            this.packetHandler.CredentialDetected+=new PacketParser.CredentialEventHandler(CredentialDetected);
            this.packetHandler.DnsRecordDetected+=new PacketParser.DnsRecordEventHandler(packetHandler_DnsRecordDetected);
            this.packetHandler.FileReconstructed+=new PacketParser.FileEventHandler(packetHandler_FileReconstructed);
            this.packetHandler.FrameDetected+=new PacketParser.FrameEventHandler(packetHandler_FrameDetected);
            this.packetHandler.KeywordDetected+=new PacketParser.KeywordEventHandler(packetHandler_KeywordDetected);
            this.packetHandler.NetworkHostDetected+=new PacketParser.NetworkHostEventHandler(packetHandler_NetworkHostDetected);
            this.packetHandler.HttpTransactionDetected += new PacketParser.HttpClientEventHandler(packetHandler_HttpTransactionDetected);
            
            this.packetHandler.ParametersDetected+=new PacketParser.ParameterEventHandler(packetHandler_ParametersDetected);
            //this.packetHandler.ParametersDetected += new PacketParser.ParameterEventHandler()
            //this.packetHandler.ParametersDetected += (s, pe) => parentForm.ParametersQueue.Enqueue(pe);

            this.packetHandler.SessionDetected+=new PacketParser.SessionEventHandler(packetHandler_SessionDetected);
            this.packetHandler.MessageDetected+=new PacketParser.MessageEventHandler(packetHandler_MessageDetected);
            this.packetHandler.MessageAttachmentDetected += new PacketParser.FileTransfer.FileStreamAssembler.FileReconsructedEventHandler(parentForm.ShowMessageAttachment);
            this.packetHandler.InsufficientWritePermissionsDetected += delegate (string path) {
                parentForm.BeginInvoke((System.Windows.Forms.MethodInvoker)delegate {
                    System.Windows.Forms.MessageBox.Show(parentForm, "User is unauthorized to access the following file:" + System.Environment.NewLine + path + System.Environment.NewLine + System.Environment.NewLine + "File(s) will not be extracted!", "Insufficient Write Permissions");
                });
            };

        }

        void packetHandler_HttpTransactionDetected(object sender, PacketParser.Events.HttpClientEventArgs he) {
            if (parentForm.GuiProperties.UseBrowsersTab)
                //parentForm.ShowHttpClient(he.HttpClientId, he.Host);
                parentForm.HttpClientQueue.Enqueue(he);
        }


        void packetHandler_MessageDetected(object sender, PacketParser.Events.MessageEventArgs me) {
            if (parentForm.GuiProperties.UseMessagesTab)
                //parentForm.ShowMessage(me.Protocol, me.SourceHost, me.DestinationHost, me.StartFrameNumber, me.StartTimestamp, me.From, me.To, me.Subject, me.Message, me.MessageEncoding, me.Attributes);
                parentForm.MessageQueue.Enqueue(me);
        }

        void packetHandler_SessionDetected(object sender, PacketParser.Events.SessionEventArgs se) {
            if (parentForm.GuiProperties.UseSessionsTab)
                parentForm.SessionQueue.Enqueue(se);
                //parentForm.ShowSession(se.Protocol, se.Client, se.Server, se.ClientPort, se.ServerPort, se.Tcp, se.StartFrameNumber, se.StartTimestamp);
        }

        void packetHandler_ParametersDetected(object sender, PacketParser.Events.ParametersEventArgs pe) {
            if (parentForm.GuiProperties.UseParametersTab)
                //parentForm.ShowParameters(pe.FrameNumber, pe.SourceHost, pe.DestinationHost, pe.SourcePort, pe.DestinationPort, pe.Parameters, pe.Timestamp, pe.Details);
                parentForm.ParametersQueue.Enqueue(pe);
        }

        void packetHandler_NetworkHostDetected(object sender, PacketParser.Events.NetworkHostEventArgs he) {
            if (parentForm.GuiProperties.UseHostsTab)
                //parentForm.ShowDetectedHost(he.Host);
                parentForm.HostQueue.Enqueue(he.Host);
        }

        void packetHandler_KeywordDetected(object sender, PacketParser.Events.KeywordEventArgs ke) {
            if (parentForm.GuiProperties.UseKeywordsTab)
                //parentForm.ShowDetectedKeyword(ke.Frame, ke.KeywordIndex, ke.KeywordLength, ke.SourceHost, ke.DestinationHost, ke.SourcePort, ke.DestinationPort);
                parentForm.KeywordQueue.Enqueue(ke);
        }

        void packetHandler_FrameDetected(object sender, PacketParser.Events.FrameEventArgs fe) {
            if(parentForm.GuiProperties.UseFramesTab)
                parentForm.ShowReceivedFrame(fe.Frame);
        }

        void packetHandler_FileReconstructed(object sender, PacketParser.Events.FileEventArgs fe) {
            if (parentForm.GuiProperties.UseFilesTab)
                //parentForm.ShowReconstructedFile(fe.File);
                parentForm.FileQueue.Enqueue(fe.File);
        }

        void packetHandler_DnsRecordDetected(object sender, PacketParser.Events.DnsRecordEventArgs de) {
            if (parentForm.GuiProperties.UseDnsTab)
                parentForm.DnsQueue.Enqueue(de);
                //parentForm.ShowDnsRecord(de.Record, de.DnsServer, de.DnsClient, de.IpPakcet, de.UdpPacket);
        }

        private void AnomalyDetected(object sender, PacketParser.Events.AnomalyEventArgs anomaly) {
            if (parentForm.GuiProperties.UseAnomaliesTab)
                parentForm.AnomalyQueue.Enqueue(anomaly);
                //parentForm.ShowAnomaly(anomaly.Message, anomaly.Timestamp);
        }
        
        private void CleartextWordsDetected(object sender, PacketParser.Events.CleartextWordsEventArgs cleartextWords) {
            if (parentForm.GuiProperties.UseCleartextTab)
                parentForm.ShowCleartextWords(cleartextWords.Words, cleartextWords.WordCharCount, cleartextWords.TotalByteCount);
        }
        private void CredentialDetected(object sender, PacketParser.Events.CredentialEventArgs credential) {
            if (parentForm.GuiProperties.UseCredentialsTab)
                //parentForm.ShowCredential(credential.Credential);
                parentForm.CredentialQueue.Enqueue(credential.Credential);
        }

        private void BufferUsageChanged(object sender, PacketParser.Events.BufferUsageEventArgs bufferUsage) {
            parentForm.SnifferBufferToolStripProgressBarNewValue = bufferUsage.BufferUsagePercent;
            //parentForm.SetBufferUsagePercent(bufferUsage.BufferUsagePercent);
        }

        internal void ResetCapturedData() {
            if(this.pcapWriter!=null && this.pcapWriter.IsOpen)
                this.pcapWriter.Close();
            this.pcapWriter=null;
            packetHandler.ResetCapturedData();

        }

        /*
        internal void SetKeywords(byte[][] keywordList) {
            this.packetHandler.KeywordList=keywordList;
        }*/

        public void StartBackgroundThreads() {
            this.packetHandler.StartBackgroundThreads();
            

        }

        public void AbortBackgroundThreads() {
            this.packetHandler.AbortBackgroundThreads();
#if DEBUG
            this.packetHandler.Disable();
#endif
        }


        //public void UpdateKeywords(IEnumerable<string> keywords) {
        public void UpdateKeywords(System.Collections.IEnumerable keywords) {
            byte[][] keywordByteArray = PacketParser.Utils.StringManglerUtil.ConvertStringsToByteArrayArray(keywords);
            packetHandler.KeywordList = keywordByteArray;
        }
        

        /// <summary>
        /// Callback method to receive packets from a sniffer
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="packet"></param>
        internal void SnifferPacketReceived(object sender, NetworkWrapper.PacketReceivedEventArgs packet) {
            if(packetHandler.TryEnqueueReceivedPacket(sender, packet)) {
                //add frame to pcap file
                if(this.pcapWriter!=null)
                    this.pcapWriter.WriteFrame(new PcapFileHandler.PcapFrame(packet.Timestamp, packet.Data, pcapWriter.DataLinkType));
            }
                
        }


    }
}
