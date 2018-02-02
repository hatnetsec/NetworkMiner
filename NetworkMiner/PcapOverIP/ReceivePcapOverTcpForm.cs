using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner.PcapOverIP {
    public partial class ReceivePcapOverTcpForm : Form, IDisposable {

        private BackgroundWorker pcapOverIpReceiver;
        private PcapTcpStream pcapTcpStream;
        private PcapFileHandler.PcapStreamReader pcapStreamReader;
        private int receivedFrames;
        private PacketParser.PacketHandler packetHandler;
        private NetworkMiner.NetworkMinerForm.AddCaseFileCallback addCaseFileCallback;
        private PcapFileHandler.PcapFileReader.CaseFileLoadedCallback caseFileLoadedCallback;
        private RunWorkerCompletedEventHandler completedEventHandler;

        public ReceivePcapOverTcpForm(PacketParser.PacketHandler packetHandler, NetworkMiner.NetworkMinerForm.AddCaseFileCallback addCaseFileCallback, PcapFileHandler.PcapFileReader.CaseFileLoadedCallback caseFileLoadedCallback, RunWorkerCompletedEventHandler completedEventHandler, ushort portNumber) {
            this.packetHandler = packetHandler;
            this.addCaseFileCallback = addCaseFileCallback;
            this.caseFileLoadedCallback = caseFileLoadedCallback;
            this.completedEventHandler = completedEventHandler;
            InitializeComponent();
            this.portNumberSelectorIncoming.Value = portNumber;
            this.startReceivingButton.Select();
        }

        private void startReceivingButton_Click(object sender, EventArgs e) {
            bool useSsl = this.useSslCheckBox.Checked;
            int idleTimeoutMilliSeconds = (int)this.timoutSelector.Value * 1000;
            if (this.incomingTcpRadioButton.Checked) {
                ushort tcpPort = (ushort)this.portNumberSelectorIncoming.Value;
                this.UpdateGui();
                try {
                    this.pcapTcpStream = new PcapTcpStream(tcpPort, useSsl, idleTimeoutMilliSeconds);
                    this.pcapTcpStream.BeginAcceptTcpClient(this.StreamEstablishedHandler);
                    this.UpdateGui();
                }
                catch (System.Net.Sockets.SocketException sockEx) {
                    MessageBox.Show("Unable to open socket, try another port number!\n\n" + sockEx.Message, "Socket Exception");
                }
            }
            else if (this.outgoingTcpRadioButton.Checked) {
                ushort tcpPort = (ushort)this.portNumberSelectorOutgoing.Value;
                try {
                    this.pcapTcpStream = new PcapTcpStream(this.ipTextBoxOutgoing.Text, tcpPort, useSsl, idleTimeoutMilliSeconds, this.StreamEstablishedHandler);
                    this.UpdateGui();
                    if (this.pcapTcpStream != null && this.pcapTcpStream.PcapStream != null)
                        this.StreamEstablishedHandler();
                }
                catch(System.Net.Sockets.SocketException) {

                }
            }
            else throw new Exception("Select either the incoming or outgoing radio button!");
        }

        void StreamEstablishedHandler() {
            if (this.pcapTcpStream != null && this.pcapTcpStream.PcapStream != null) {
                //Application.DoEvents();
                try {
                    this.pcapStreamReader = new PcapFileHandler.PcapStreamReader(this.pcapTcpStream.PcapStream, 1000, null, true, long.MaxValue, this.pcapTcpStream.IdleTimeoutMilliSeconds);
                    this.pcapStreamReader.StreamIsClosedFunction = new PcapFileHandler.PcapStreamReader.StreamIsClosed(this.pcapTcpStream.IsClosed);


                    //Application.DoEvents();


                    this.pcapOverIpReceiver = new BackgroundWorker();
                    this.pcapOverIpReceiver.DoWork += new DoWorkEventHandler(pcapOverIpReceiver_DoWork);
                    this.pcapOverIpReceiver.RunWorkerCompleted += new RunWorkerCompletedEventHandler(pcapOverIpReceiver_RunWorkerCompleted);
                    this.pcapOverIpReceiver.RunWorkerCompleted += this.completedEventHandler;
                    this.pcapOverIpReceiver.WorkerSupportsCancellation = true;
                    this.pcapOverIpReceiver.RunWorkerAsync();

                    BackgroundWorker guiUpdater = new BackgroundWorker();
                    guiUpdater.DoWork += new DoWorkEventHandler(guiUpdater_DoWork);
                    guiUpdater.RunWorkerAsync();
                }
                catch (Exception e) {
                    this.BeginInvoke((MethodInvoker)delegate() { MessageBox.Show(this, e.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); });
                    this.CloseStreamReaderObjects();
                }

            }
            else {
                this.CloseStreamReaderObjects();
            }
            this.UpdateGui();

        }

        void guiUpdater_DoWork(object sender, DoWorkEventArgs e) {
            while (this.pcapOverIpReceiver.IsBusy && !this.pcapOverIpReceiver.CancellationPending) {
                System.Threading.Thread.Sleep(1000);
                this.UpdateGui();
                //Application.DoEvents();
            }
        }

        void pcapOverIpReceiver_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e) {
            bool reconnect = this.pcapTcpStream == null || this.pcapTcpStream.SocketState != PcapTcpStream.TcpSocketState.Closed;
            this.CloseStreamReaderObjects();
            //this.Close();
            if(reconnect)
                this.startReceivingButton_Click(sender, e);//start a new listener to receive more data
        }

        private void UpdateGui() {
            if (InvokeRequired) {
                this.BeginInvoke((MethodInvoker)delegate() { this.UpdateGui(); });
            }
            else {
                PcapTcpStream.TcpSocketState tcpState = PcapTcpStream.TcpSocketState.Closed;
                if (this.pcapTcpStream != null)
                    tcpState = this.pcapTcpStream.SocketState;

                this.socketStateValueLabel.Text = tcpState.ToString();
                this.receivedFramesValueLabel.Text = this.receivedFrames.ToString();

                if (tcpState == PcapTcpStream.TcpSocketState.Connected || tcpState == PcapTcpStream.TcpSocketState.Receiving && this.pcapTcpStream.RemoteIP != null) {
                    if (tcpState == PcapTcpStream.TcpSocketState.Connected)
                        this.socketStateValueLabel.Text +=  " to " + this.pcapTcpStream.RemoteIP.ToString();
                    else if (tcpState == PcapTcpStream.TcpSocketState.Receiving)
                        this.socketStateValueLabel.Text += " from " + this.pcapTcpStream.RemoteIP.ToString();

                }

                if (tcpState == PcapTcpStream.TcpSocketState.Closed && (!this.startReceivingButton.Enabled || this.stopButton.Enabled)) {
                    this.startReceivingButton.Enabled = true;
                    this.stopButton.Enabled = false;
                    this.portNumberSelectorIncoming.Enabled = true;
                    this.useSslCheckBox.Enabled = true;
                    this.timoutSelector.Enabled = true;
                    this.inOutTcpRadioButton_CheckedChanged(this, null);
                }
                else if (tcpState != PcapTcpStream.TcpSocketState.Closed && (this.startReceivingButton.Enabled || !this.stopButton.Enabled)) {
                    this.startReceivingButton.Enabled = false;
                    this.stopButton.Enabled = true;
                    this.portNumberSelectorIncoming.Enabled = false;
                    this.useSslCheckBox.Enabled = false;
                    this.timoutSelector.Enabled = false;

                    this.portNumberSelectorIncoming.Enabled = false;
                    this.portNumberSelectorOutgoing.Enabled = false;
                    this.ipTextBoxOutgoing.Enabled = false;
                }
            }
        }

        void pcapOverIpReceiver_DoWork(object sender, DoWorkEventArgs e) {
            this.receivedFrames = 0;
            DateTime lastGuiUpdateTime = DateTime.Now;
            TimeSpan updateRate = new TimeSpan(2000000);

            DateTime firstFrameTimestamp = DateTime.MinValue;
            DateTime lastFrameTimestamp = DateTime.MinValue;

            string filename = PcapFileHandler.Tools.GenerateCaptureFileName(DateTime.Now);
            string fileFullPath = this.packetHandler.OutputDirectory + "Captures" + System.IO.Path.DirectorySeparatorChar + filename;
            //string fileFullPath = System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath)) + System.IO.Path.DirectorySeparatorChar + "Captures" + System.IO.Path.DirectorySeparatorChar + filename;

            PcapFileHandler.PcapFileWriter pcapFileWriter = new PcapFileHandler.PcapFileWriter(fileFullPath, this.pcapStreamReader.FileDataLinkType[0]);
            //this.caseFileLoadedCallback(
            this.addCaseFileCallback(fileFullPath, filename);

            using(pcapFileWriter) {

                
                //foreach (PcapFileHandler.PcapPacket pcapPacket in this.pcapStreamReader.PacketEnumerator(delegate() { Application.DoEvents(); }, null)) {
                foreach (PcapFileHandler.PcapFrame pcapPacket in this.pcapStreamReader.PacketEnumerator()) {
                    this.receivedFrames++;
                    if(this.pcapTcpStream.SocketState == PcapTcpStream.TcpSocketState.Connected)
                        this.pcapTcpStream.SocketState = PcapTcpStream.TcpSocketState.Receiving;
                    pcapFileWriter.WriteFrame(pcapPacket);
                    if(firstFrameTimestamp == DateTime.MinValue)
                        firstFrameTimestamp = pcapPacket.Timestamp;
                    lastFrameTimestamp = pcapPacket.Timestamp;

                    int millisecondsToSleep = 1;
                    while (this.packetHandler.FramesInQueue > 100) { //This can become a for-ever loop if packetHandler chokes and hangs might might be a good idea to do a this.pcapStreamReader.AbortFileRead() and throw an exception?
                        System.Threading.Thread.Sleep(millisecondsToSleep);
                        if (millisecondsToSleep < 200)
                            millisecondsToSleep *= 2;
                        //Application.DoEvents();//REMOVED 2014-06-24
                    }
                    PacketParser.Frame frame = packetHandler.GetFrame(pcapPacket.Timestamp, pcapPacket.Data, pcapPacket.DataLinkType);
                    packetHandler.AddFrameToFrameParsingQueue(frame);

                    if (DateTime.Now > lastGuiUpdateTime.Add(updateRate)) {
                        //we need to update the GUI
                    

                        this.UpdateGui();
                        lastGuiUpdateTime = DateTime.Now;
                    }
                    if (this.pcapOverIpReceiver.CancellationPending)
                        break;
                }
            }
            this.UpdateGui();
            this.caseFileLoadedCallback(fileFullPath, this.receivedFrames, firstFrameTimestamp, lastFrameTimestamp);
        }

        private void ReceivePcapOverTcpForm_FormClosing(object sender, FormClosingEventArgs e) {
            this.CloseStreamReaderObjects();
        }

        private void CloseStreamReaderObjects() {

            if (this.pcapOverIpReceiver != null)
                this.pcapOverIpReceiver.CancelAsync();
            if (this.pcapStreamReader != null)
                this.pcapStreamReader.Dispose();
            if (this.pcapTcpStream != null)
                this.pcapTcpStream.Dispose();
            this.UpdateGui();
        }

        void IDisposable.Dispose() {
            this.CloseStreamReaderObjects();
        }

        private void stopButton_Click(object sender, EventArgs e) {
            this.CloseStreamReaderObjects();
            
        }

        private void inOutTcpRadioButton_CheckedChanged(object sender, EventArgs e) {
            if (this.incomingTcpRadioButton.Checked) {
                this.portNumberSelectorIncoming.Enabled = true;
                this.portNumberSelectorOutgoing.Enabled = false;
                this.ipTextBoxOutgoing.Enabled = false;
            }
            else {
                this.portNumberSelectorIncoming.Enabled = false;
                this.portNumberSelectorOutgoing.Enabled = true;
                this.ipTextBoxOutgoing.Enabled = true;
            }
        }
    }
}
