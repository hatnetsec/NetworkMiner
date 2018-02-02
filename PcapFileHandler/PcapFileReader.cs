using System;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PcapFileHandler {
    public class PcapFileReader : PcapStreamReader {

        public delegate void CaseFileLoadedCallback(string filePathAndName, int framesCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp);

        private string filename;
        private System.IO.FileStream fileStream;
        private CaseFileLoadedCallback caseFileLoadedCallback;


        public string Filename {
            get {
                return this.filename;
            }
        }

        public new long Position {
            get { return this.fileStream.Position; }
            set { this.fileStream.Position = value; }
        }

        public int PercentRead {
            get {
                //the stream might be closed if we have read it through...
                return (int)(((this.fileStream.Position - this.PacketBytesInQueue) * 100) / this.fileStream.Length);
            }
        }

        public PcapFileReader(string filename) : this(filename, 1000, null) { }
        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback) : this(filename, packetQueueSize, readCompleteCallback, true) { }

        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, FileShare fileShare) : this(filename, packetQueueSize, readCompleteCallback, true, fileShare) { }

        public PcapFileReader(string filename, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, bool startBackgroundWorkers, FileShare fileShare = FileShare.Read)
            : this(filename, new System.IO.FileStream(filename, FileMode.Open, FileAccess.Read, fileShare, 262144, FileOptions.SequentialScan), packetQueueSize, readCompleteCallback, startBackgroundWorkers) { }

        private PcapFileReader(string filename, System.IO.FileStream fileStream, int packetQueueSize, CaseFileLoadedCallback readCompleteCallback, bool startBackgroundWorkers)
            : base(fileStream, packetQueueSize, null, startBackgroundWorkers, fileStream.Length) {
            this.filename = filename;
            this.fileStream = fileStream;
            //base.streamLength = fileStream.Length;
            base.streamReadCompletedCallback = new StreamReadCompletedCallback(this.StreamReadCompletedCallbackHandler);
            this.caseFileLoadedCallback = readCompleteCallback;
        }

        public void StreamReadCompletedCallbackHandler(int framesCount, DateTime fistFrameTimestamp, DateTime lastFrameTimestamp) {
            if(this.caseFileLoadedCallback != null)
                this.caseFileLoadedCallback(this.filename, framesCount, fistFrameTimestamp, lastFrameTimestamp);
        }


    }
}
