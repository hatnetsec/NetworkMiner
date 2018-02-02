using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public class PcapParser : IPcapParser {

        public const uint LIBPCAP_MAGIC_NUMBER = 0xa1b2c3d4;

        //private System.IO.Stream pcapStream;
        //private PcapStreamReader.AbortReadingDelegate abortReading;
        private PcapFrame.DataLinkTypeEnum dataLinkType;
        private IPcapStreamReader pcapStreamReader;

        private bool littleEndian;

        private List<KeyValuePair<string, string>> metadata;


        /*public PcapFrame.DataLinkTypeEnum CurrentDataLinkType {
            get { return this.dataLinkType; }
        }*/

        public List<KeyValuePair<string, string>> Metadata {
            get { return this.metadata; }
        }

        public IList<PcapFrame.DataLinkTypeEnum> DataLinkTypes {
            get { return new PcapFrame.DataLinkTypeEnum[] { this.dataLinkType}; }
        }

        public PcapParser(IPcapStreamReader pcapStreamReader)
            : this(pcapStreamReader, null) {

        }

        public PcapParser(IPcapStreamReader pcapStreamReader, byte[] firstFourBytes) {
            this.pcapStreamReader = pcapStreamReader;
            this.metadata = new List<KeyValuePair<string, string>>();

            //read pcap file header!
            byte[] buffer4 = new byte[4];//32 bits is suitable
            byte[] buffer2 = new byte[2];//16 bits is sometimes needed
            //uint wiresharkMagicNumber = 0xa1b2c3d4;

            //Section Header Block (mandatory)
            if (firstFourBytes == null || firstFourBytes.Length != 4)
                try {
                    buffer4 = this.pcapStreamReader.BlockingRead(4);
                }
                catch(NullReferenceException) {
                    throw new System.IO.InvalidDataException("The stream is too short, it does not contain a full PCAP header.");
                }
            else
                buffer4 = firstFourBytes;

            if (this.ToUInt32(buffer4, false) == LIBPCAP_MAGIC_NUMBER) {
                this.littleEndian = false;
                this.metadata.Add(new KeyValuePair<string,string>("Endianness", "Big Endian"));
            }
            else if (this.ToUInt32(buffer4, true) == LIBPCAP_MAGIC_NUMBER) {
                this.littleEndian = true;
                this.metadata.Add(new KeyValuePair<string,string>("Endianness", "Little Endian"));
            }
            else
                throw new System.IO.InvalidDataException("The stream is not a PCAP file. Magic number is " + this.ToUInt32(buffer4, false).ToString("X2") + " or " + this.ToUInt32(buffer4, true).ToString("X2") + " but should be " + LIBPCAP_MAGIC_NUMBER.ToString("X2") + ".");

            /* major version number */
            this.pcapStreamReader.BlockingRead(buffer2, 0, 2);
            ushort majorVersionNumber = ToUInt16(buffer2, this.littleEndian);
            /* minor version number */
            this.pcapStreamReader.BlockingRead(buffer2, 0, 2);
            ushort minorVersionNumber = ToUInt16(buffer2, this.littleEndian);
            /* GMT to local correction */
            this.pcapStreamReader.BlockingRead(buffer4, 0, 4);
            int timezoneOffsetSeconds = (int)ToUInt32(buffer4, this.littleEndian);
            /* accuracy of timestamps */
            this.pcapStreamReader.BlockingRead(buffer4, 0, 4);
            /* max length of captured packets, in octets */
            this.pcapStreamReader.BlockingRead(buffer4, 0, 4);
            uint maximumPacketSize = ToUInt32(buffer4, this.littleEndian);
            /* data link type */
            this.pcapStreamReader.BlockingRead(buffer4, 0, 4); //offset = 20 = 0x14
            this.dataLinkType = (PcapFrame.DataLinkTypeEnum)ToUInt32(buffer4, this.littleEndian);
            this.metadata.Add(new KeyValuePair<string, string>("Data Link Type", dataLinkType.ToString()));
        }

        public PcapFrame ReadPcapPacketBlocking() {
            //byte[] buffer4 = new byte[4];//32 bits is suitable
            /* timestamp seconds */
            //buffer4 = ;
            long seconds = (long)ToUInt32(this.pcapStreamReader.BlockingRead(4), this.littleEndian);/*seconds since January 1, 1970 00:00:00 GMT*/
            /* timestamp microseconds */
            //this.pcapStream.Read(buffer4, 0, 4);
            //buffer4 = ;
            uint microseconds = ToUInt32(this.pcapStreamReader.BlockingRead(4), this.littleEndian);
            /* number of octets of packet saved in file */
            //this.pcapStream.Read(buffer4, 0, 4);
            //buffer4 = ;
            int bytesToRead = (int)ToUInt32(this.pcapStreamReader.BlockingRead(4), this.littleEndian);
            if (bytesToRead > PcapStreamReader.MAX_FRAME_SIZE)
                throw new Exception("Frame size is too large! Frame size = " + bytesToRead);
            else if (bytesToRead < 0)
                throw new Exception("Cannot read frames of negative sizes! Frame size = " + bytesToRead);
            /* actual length of packet */
            //this.pcapStream.Read(buffer4, 0, 4);
            this.pcapStreamReader.BlockingRead(4);//don't need this value

            byte[] data = this.pcapStreamReader.BlockingRead(bytesToRead);

            DateTime timestamp = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long tics = (seconds * 1000000 + microseconds) * 10;
            TimeSpan timespan = new TimeSpan(tics);

            return new PcapFrame(timestamp.Add(timespan), data, this.dataLinkType);
        }


        /*
            byte[] buffer = new byte[bytesToRead];
            int bytesRead = this.pcapStream.Read(buffer, 0, bytesToRead);
            int sleepMilliSecs = 20;
            while (bytesRead < bytesToRead) {
                //no more data available to read at this moment
                //if (this.backgroundFileReader.CancellationPending || this.EndOfStream() || (this.streamIsClosed != null && this.streamIsClosed())) {
                if (abortReading != null && abortReading()) {
                    this.pcapStream = null;
                    throw new System.IO.EndOfStreamException("Done reading");
                }

                if (sleepMilliSecs++ > 200) {
                    //Give up reading!
                    this.pcapStream = null;
                    throw new Exception("Stream reading timed out...");
                }
                System.Threading.Thread.Sleep(sleepMilliSecs);
                bytesRead += this.pcapStream.Read(buffer, bytesRead, bytesToRead - bytesRead);

            }
            return buffer;
        }*/

        private ushort ToUInt16(byte[] buffer, bool littleEndian) {
            if (littleEndian)
                return (ushort)(buffer[0] ^ buffer[1] << 8);
            else
                return (ushort)(buffer[0] << 8 ^ buffer[1]);
        }

        private uint ToUInt32(byte[] buffer, bool littleEndian) {
            if (littleEndian) {//swapped
                return (uint)(buffer[0] ^ buffer[1] << 8 ^ buffer[2] << 16 ^ buffer[3] << 24);
            }
            else//normal
                return (uint)(buffer[0] << 24 ^ buffer[1] << 16 ^ buffer[2] << 8 ^ buffer[3]);
        }





        
    }
}
