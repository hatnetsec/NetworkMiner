using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public class PcapStreamReader : IDisposable, IPcapStreamReader {
        public delegate void EmptyDelegate();
        public delegate bool StreamIsClosed();
        public delegate bool AbortReadingDelegate();
        //public delegate void ReadCompletedCallback(string filePathAndName, int framesCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp);
        public delegate void StreamReadCompletedCallback(int framesCount, DateTime firstFrameTimestamp, DateTime lastFrameTimestamp);

        public event UnhandledExceptionEventHandler UnhandledException;

        public static IPcapParserFactory PcapParserFactory = new PcapParserFactory();

        //private string filename;
        //private System.IO.FileStream fileStream;
        private System.IO.Stream pcapStream;
        private long streamLength;
        private long readBytesEstimate;
        private IPcapParser pcapParser;
        //private bool littleEndian;//is false if file format is Big endian
        //private ushort majorVersionNumber;
        //private ushort minorVersionNumber;
        //private int timezoneOffsetSeconds;//GMT + 1:00 (Paris, Berlin, Stockholm) => -3600
        //private uint maximumPacketSize;//snaplen
        //private DataLinkType dataLinkType;

        private System.ComponentModel.BackgroundWorker backgroundStreamReader;
        private System.Collections.Generic.Queue<PcapFrame> packetQueue;//private const int PACKET_QUEUE_SIZE=4000;
        private int packetQueueMaxSize;
        private System.Threading.AutoResetEvent packetQueueHasRoomEvent;


        private int enqueuedByteCount;
        private int dequeuedByteCount;
        private StreamIsClosed streamIsClosed;
        //private long pcapHeaderSize;//number of bytes into the pcap where the packets start (always 24)

        private int readTimeoutMilliseconds = 20000;//20s

        protected StreamReadCompletedCallback streamReadCompletedCallback;

        public const int MAX_FRAME_SIZE = 131072;//Gigabit Ethernet Jumbo Frames are 9000 bytes (this is 15 times larger, so we should be safe)

        //[System.Obsolete("Data Link info is now available in PcapFileHandler.PcapPacket instead!")]
        public IList<PcapFrame.DataLinkTypeEnum> FileDataLinkType { get { return this.pcapParser.DataLinkTypes; } }

        public StreamIsClosed StreamIsClosedFunction { set { this.streamIsClosed = value; } }

        public long Position {
            get {
                if (this.pcapStream.CanSeek)
                    return this.pcapStream.Position;
                else
                    return this.readBytesEstimate;
            }
        }
        public List<KeyValuePair<string, string>> PcapParserMetadata { get { return this.pcapParser.Metadata; } }

        public IPcapParser PcapParser { get { return this.pcapParser; } }

        public PcapStreamReader(System.IO.Stream pcapStream) : this(pcapStream, 1000, null) { }
        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, true) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue) { }

        public PcapStreamReader(System.IO.FileStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue, 20000) { }


        public PcapStreamReader(System.Net.Security.SslStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue, pcapStream.ReadTimeout) { }

        public PcapStreamReader(System.Net.Sockets.NetworkStream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, long.MaxValue, pcapStream.ReadTimeout) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength)
            : this(pcapStream, packetQueueSize, streamReadCompletedCallback, startBackgroundWorkers, streamMaxLength, /*20000*/ pcapStream.ReadTimeout) { }

        public PcapStreamReader(System.IO.Stream pcapStream, int packetQueueSize, StreamReadCompletedCallback streamReadCompletedCallback, bool startBackgroundWorkers, long streamMaxLength, int readTimeoutMilliseconds) {
        
            this.pcapStream = pcapStream;
            this.streamLength = streamMaxLength;
            this.readBytesEstimate = 0;
            this.readTimeoutMilliseconds = readTimeoutMilliseconds;

            this.packetQueueMaxSize=packetQueueSize;
            this.streamReadCompletedCallback=streamReadCompletedCallback;


            //TODO: Figure out if it is a libpcap or pcapNG stream...
            this.pcapParser = PcapParserFactory.CreatePcapParser(this);// new PcapParser(pcapStream, this.AbortReadingPcapStream);
            /*
            byte[] buffer4=new byte[4];//32 bits is suitable
            byte[] buffer2=new byte[2];//16 bits is sometimes needed
            uint wiresharkMagicNumber=0xa1b2c3d4;

            //Section Header Block (mandatory)

            this.pcapStream.Read(buffer4, 0, 4);

            if(wiresharkMagicNumber==this.ToUInt32(buffer4, false))
                this.littleEndian=false;
            else if(wiresharkMagicNumber==this.ToUInt32(buffer4, true))
                this.littleEndian=true;
            else
                throw new System.IO.InvalidDataException("The stream is not a PCAP file. Magic number is "+this.ToUInt32(buffer4, false).ToString("X2")+" or "+this.ToUInt32(buffer4, true).ToString("X2")+" but should be "+wiresharkMagicNumber.ToString("X2")+".");

            
            this.pcapStream.Read(buffer2, 0, 2);
            this.majorVersionNumber=ToUInt16(buffer2, this.littleEndian);
            
            this.pcapStream.Read(buffer2, 0, 2);
            this.minorVersionNumber=ToUInt16(buffer2, this.littleEndian);
            
            this.pcapStream.Read(buffer4, 0, 4);
            this.timezoneOffsetSeconds=(int)ToUInt32(buffer4, this.littleEndian);
            
            this.pcapStream.Read(buffer4, 0, 4);
            
            this.pcapStream.Read(buffer4, 0, 4);
            this.maximumPacketSize=ToUInt32(buffer4, this.littleEndian);
            
            this.pcapStream.Read(buffer4, 0, 4); //offset = 20 = 0x14
            this.dataLinkType=(DataLinkType)ToUInt32(buffer4, this.littleEndian);
            */
            //this.pcapHeaderSize = this.pcapStream.Position;

            this.backgroundStreamReader=new System.ComponentModel.BackgroundWorker();
            this.backgroundStreamReader.WorkerSupportsCancellation = true;
            this.packetQueue=new Queue<PcapFrame>(this.packetQueueMaxSize);
            this.packetQueueHasRoomEvent = new System.Threading.AutoResetEvent(true);
            this.enqueuedByteCount=0;
            this.dequeuedByteCount=0;
            if (startBackgroundWorkers)
                this.StartBackgroundWorkers();
        }

        ~PcapStreamReader() {
            //close the file stream here at least (instead of at the WorkerCompleted event)
            if (this.pcapStream != null) {
                this.pcapStream.Close();
                this.pcapStream = null;
            }
            this.streamReadCompletedCallback = null;
        }



        public int PacketBytesInQueue {
            get { return this.enqueuedByteCount - this.dequeuedByteCount; }
        }

        private bool EndOfStream() {
            //first check if we have any clue about when the stream ends
            if (this.pcapStream == null)
                return true;
            if (!this.pcapStream.CanRead)
                return true;
            if (this.streamLength == long.MaxValue)
                return false;
            else if (this.pcapStream.CanSeek)
                return this.pcapStream.Position >= this.streamLength;
            else {
                try {
                    return this.pcapStream.Position >= this.streamLength;
                }
                catch {
                    return false;
                }
            }
        }

        public void StartBackgroundWorkers() {
            this.backgroundStreamReader.DoWork+=new System.ComponentModel.DoWorkEventHandler(backgroundStreamReader_DoWork);
            this.backgroundStreamReader.WorkerSupportsCancellation=true;
            this.backgroundStreamReader.RunWorkerCompleted+=new System.ComponentModel.RunWorkerCompletedEventHandler(backgroundFileReader_RunWorkerCompleted);
            this.backgroundStreamReader.RunWorkerAsync();
        }

        void backgroundFileReader_RunWorkerCompleted(object sender, System.ComponentModel.RunWorkerCompletedEventArgs e) {
            //do some cleanup
            //this.fileStream.Close();//the file handle might be needed later on to see the position
            //this.packetQueue.Clear();
        }

        public void AbortFileRead() {
            this.backgroundStreamReader.CancelAsync();
            this.packetQueue.Clear();
        }

        public void ThreadStart() {
            try {
                this.backgroundStreamReader_DoWork(this, new System.ComponentModel.DoWorkEventArgs(null));
            }
            catch (System.Threading.ThreadAbortException) {
                this.AbortFileRead();
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

        void backgroundStreamReader_DoWork(object sender, System.ComponentModel.DoWorkEventArgs e) {
            DateTime firstFrameTimestamp=DateTime.MinValue;
            DateTime lastFrameTimestamp=DateTime.MinValue;
            int framesCount=0;
            try {
                //int sleepMilliSecs = 20;
                
                
                while (!this.backgroundStreamReader.CancellationPending && !this.EndOfStream()) {
                    if (this.packetQueue.Count < this.packetQueueMaxSize) {
                        PcapFrame packet = this.pcapParser.ReadPcapPacketBlocking();
                        if (firstFrameTimestamp == DateTime.MinValue)
                            firstFrameTimestamp = packet.Timestamp;
                        lastFrameTimestamp = packet.Timestamp;
                        framesCount++;
                        lock (this.packetQueue) {
                            this.packetQueue.Enqueue(packet);
                        }
                        this.enqueuedByteCount += packet.Data.Length;
                        //sleepMilliSecs = 20;
                    }
                    else {
                        this.packetQueueHasRoomEvent.WaitOne();
                        /*System.Threading.Thread.Sleep(sleepMilliSecs);
                        if (sleepMilliSecs < 1000)
                            sleepMilliSecs+=10;*/
                    }
                }
            }
            catch (System.IO.EndOfStreamException) {
                //Do nothing, just stop reading
                this.pcapStream = null;
            }
            catch (System.IO.IOException) {
                //probably a socket timout
                if(!(this.pcapStream is System.IO.FileStream) && this.pcapStream != null)
                    this.pcapStream.Close();
                //this.pcapStream = null;
            }

#if !DEBUG
            catch (Exception ex) {
                this.pcapStream = null;
                e.Cancel = true;
                e.Result = ex.Message;
                this.AbortFileRead();
            }
#endif
            //do a callback with this.filename as well as first and last timestamp
            if(this.streamReadCompletedCallback!=null && firstFrameTimestamp!=DateTime.MinValue && lastFrameTimestamp!=DateTime.MinValue)
                this.streamReadCompletedCallback(framesCount, firstFrameTimestamp, lastFrameTimestamp);
        }

        public IEnumerable<PcapFrame> PacketEnumerator() {
            return PacketEnumerator(null, null);
        }

        public IEnumerable<PcapFrame> PacketEnumerator(EmptyDelegate waitFunction, StreamReadCompletedCallback captureCompleteCallback) {

            int sleepMilliSecs = 20;


            int maxSleepMS = (int)Math.Sqrt(2.0 * this.readTimeoutMilliseconds);//200*200/2 = 20.000 = 20 seconds
            maxSleepMS += sleepMilliSecs;//to make sure BlockingRead timeouts before
            while (!this.backgroundStreamReader.CancellationPending && (this.backgroundStreamReader.IsBusy || !this.EndOfStream() || this.packetQueue.Count > 0)) {
                if(this.packetQueue.Count>0) {
                    sleepMilliSecs = 20;
                    PcapFrame packet;
                    lock(this.packetQueue) {
                        packet=this.packetQueue.Dequeue();
                    }
                    this.dequeuedByteCount+=packet.Data.Length;
                    if (this.packetQueue.Count < this.packetQueueMaxSize / 2)
                        this.packetQueueHasRoomEvent.Set();
                    yield return packet;
                }
                else {
                    if (sleepMilliSecs++ > maxSleepMS) {//200*200/2 = 20.000 = 20 seconds
                        //abort the reading, something has gone wrong...
                        yield break;
                    }
                    if(waitFunction != null)
                        waitFunction();
                    else
                        System.Threading.Thread.Sleep(sleepMilliSecs);
                }
            }

            //yield break;
        }


        public bool AbortReadingPcapStream() {
            return this.backgroundStreamReader.CancellationPending || this.EndOfStream() || (this.streamIsClosed != null && this.streamIsClosed());
        }

        public byte[] BlockingRead(int bytesToRead) {
            byte[] buffer = new byte[bytesToRead];
            BlockingRead(buffer, 0, bytesToRead);
            return buffer;
        }

        //public static int BlockingRead(System.IO.Stream stream, int bytesToRead, PcapStreamReader.AbortReadingDelegate abortReading, byte[] buffer, int writeOffset) {
        public int BlockingRead(byte[] buffer, int offset, int count) {
            int bytesRead = this.pcapStream.Read(buffer, offset, count);
            if (bytesRead == 0) {
                throw new System.IO.EndOfStreamException("Done reading");
            }
            int sleepMilliSecs = 20;
            int maxSleepMS = (int)Math.Sqrt(2.0 * this.readTimeoutMilliseconds);
            while (bytesRead < count) {
                //no more data available to read at this moment
                //if (this.backgroundFileReader.CancellationPending || this.EndOfStream() || (this.streamIsClosed != null && this.streamIsClosed())) {
                if (this.AbortReadingPcapStream()) {
                    throw new System.IO.EndOfStreamException("Done reading");
                }

                if (sleepMilliSecs++ > maxSleepMS) {
                    //Give up reading! (total idle wait time ~8.2 seconds [128*128/2=8192] )
                    throw new System.IO.IOException("Stream reading timed out...");
                }
                System.Threading.Thread.Sleep(sleepMilliSecs);
                bytesRead += this.pcapStream.Read(buffer, bytesRead, count - bytesRead);

            }
            this.readBytesEstimate += bytesRead;
            return bytesRead;
        }


#region IDisposable Members

        public void Dispose() {
            //throw new Exception("The method or operation is not implemented.");
            if(this.backgroundStreamReader!=null)
                this.backgroundStreamReader.CancelAsync();
            if (this.pcapStream != null) {
                this.pcapStream.Close();
                this.pcapStream = null;
            }
        }

#endregion
    }
}
