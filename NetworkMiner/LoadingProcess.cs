using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;


namespace NetworkMiner {
    public partial class LoadingProcess : Form {

        private int percent;
        private PcapFileHandler.PcapFileReader pcapReader;
        private bool isAborted;

        private BackgroundWorker worker;
        private CaseFile caseFile;
        private Timer guiUpdateTimer;

        internal delegate void SetLoadingProcessValue(int percent);
        //internal delegate System.Windows.Forms.DialogResult ShowLoadingProcess();
        internal delegate void ShowLoadingProcess();

        public bool IsAborted { get { return this.isAborted; } }
        public PcapFileHandler.PcapFileReader PcapReader { get { return this.pcapReader; } }
        public BackgroundWorker Worker { get { return this.worker; } set { this.worker=value; } }
        public CaseFile CaseFile { get { return this.caseFile; } }

        internal int Percent {
            get { return this.percent; }
            set {
                if(value>=0 && value<=100) {
                    this.percent=value;
                    //this.percentLabel.Text=""+percent+"%";
                    //this.progressBar1.Value=percent;
                }
            }
        }

        internal LoadingProcess(PcapFileHandler.PcapFileReader pcapReader, CaseFile caseFile)
            : this() {

            this.caseFile = caseFile;
            this.pcapReader=pcapReader;
            this.textLabel.Text=caseFile.Filename;
            this.progressBar1.Value=0;
            this.percent=0;
            this.percentLabel.Text=""+percent+" %";
            this.isAborted=false;
        }


        private LoadingProcess() {
            InitializeComponent();
            this.guiUpdateTimer = new Timer();
            this.guiUpdateTimer.Interval = NetworkMinerForm.GUI_UPDATE_INTERVAL_MS;
            this.guiUpdateTimer.Tick += this.GuiUpdateTimer_Tick;
            this.guiUpdateTimer.Start();
        }

        private void GuiUpdateTimer_Tick(object sender, EventArgs e) {
            if (this.Visible && this.IsHandleCreated) {
                if (this.progressBar1.Value != this.percent) {
                    this.percentLabel.Text = "" + percent + "%";
                    this.progressBar1.Value = this.percent;
                    //PacketParser.Utils.Logger.Log("Percent parsed: " + this.percent, System.Diagnostics.EventLogEntryType.Information);
                }
            }
        }

        private void LoadingProcess_FormClosing(object sender, FormClosingEventArgs e) {
            //PacketParser.Utils.Logger.Log("Closing loading process form", System.Diagnostics.EventLogEntryType.Information);
            this.isAborted=true;
            this.guiUpdateTimer.Stop();
            pcapReader.AbortFileRead();
            this.worker.CancelAsync();
            //PacketParser.Utils.Logger.Log("Closed loading process form", System.Diagnostics.EventLogEntryType.Information);
        }
    }
}