using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Utils {
    class StreamReassembler {
        private readonly byte[] DATA_TERMINATOR; //CRLF.CRLF
        private System.IO.MemoryStream dataStream; //to hold the DATA part of an email
        private System.Text.ASCIIEncoding asciiEncoding;
        private bool terminatorFound;
        private int postTerminatorSkipBytes;//for example 2 in otder to skip <cr><lf> after a <cr><lf>.<cr><lf> sequence

        internal System.IO.MemoryStream DataStream { get { return this.dataStream; } set { this.dataStream = value; } }
        internal bool TerminatorFound { get { return this.terminatorFound; } }

        internal StreamReassembler(byte[] terminator, int postTerminatorSkipBytes) {
            this.DATA_TERMINATOR = terminator;
            this.postTerminatorSkipBytes = postTerminatorSkipBytes;
            this.dataStream = new System.IO.MemoryStream();
            this.asciiEncoding = new System.Text.ASCIIEncoding();
            this.terminatorFound = false;
        }

        internal int AddData(string dataString) {
            byte[] data = asciiEncoding.GetBytes(dataString);
            return this.AddData(data, 0, data.Length);
        }

        /// <summary>
        /// Add data to a data stream until a terminator is found. The terminator will not be included in the extracted data unless postTerminatorSkipBytes == length of terminator
        /// </summary>
        /// <param name="buffer"></param>
        /// <param name="offset"></param>
        /// <param name="count"></param>
        /// <returns>Bytes read from the buffer, including terminator.</returns>
        internal int AddData(byte[] buffer, int offset, int count) {
            List<byte> readBytes;

            long terminatorIndex = Utils.KnuthMorrisPratt.ReadTo(DATA_TERMINATOR, buffer, offset, out readBytes);
            int bytesRead = 0;
            //terminator might be split in between two packets
            if (terminatorIndex == -1 && this.dataStream.Length > 0) {
                int oldBytesToRead = Math.Min(DATA_TERMINATOR.Length - 1, (int)dataStream.Length);
                byte[] oldBufferTail = new byte[oldBytesToRead];
                this.dataStream.Seek(this.dataStream.Length - oldBytesToRead, System.IO.SeekOrigin.Begin);
                int oldBytesRead = this.dataStream.Read(oldBufferTail, 0, oldBytesToRead);
                byte[] tempBuffer = new byte[oldBytesRead + buffer.Length - offset];
                Array.Copy(oldBufferTail, 0, tempBuffer, 0, oldBytesRead);
                Array.Copy(buffer, offset, tempBuffer, oldBytesRead, buffer.Length - offset);
                long tempTerminatorIndex = Utils.KnuthMorrisPratt.ReadTo(DATA_TERMINATOR, tempBuffer, 0, out readBytes);
                if (tempTerminatorIndex >= 0) {
                    bytesRead = (int)tempTerminatorIndex - oldBytesRead + DATA_TERMINATOR.Length;
                    count = (int)tempTerminatorIndex - oldBytesRead + this.postTerminatorSkipBytes;
                    this.terminatorFound = true;
                }
                else
                    bytesRead = count;
            }
            else if (terminatorIndex >= 0) {
                //terminator was found
                bytesRead = (int)terminatorIndex - offset + DATA_TERMINATOR.Length;
                //the final <cr><lf>.<cr><lf> will not included, but let's at least add one <cr><lf> at the end
                count = (int)terminatorIndex - offset + this.postTerminatorSkipBytes; //"+2" adds the <cr><lf>
                this.terminatorFound = true;
            }
            else
                bytesRead = count;
            if (count > 0) {
                this.dataStream.Seek(0, System.IO.SeekOrigin.End);
                this.dataStream.Write(buffer, offset, count);
            }
            return bytesRead;
        }

        internal void Close() {
            this.dataStream.Close();
            this.dataStream = null;
        }

    }
}
