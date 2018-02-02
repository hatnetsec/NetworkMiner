using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Mime {
    class ByteArrayStream : System.IO.Stream{
        private byte[] data;
        private long index;

        public ByteArrayStream(byte[] data, long startIndex) {
            this.data=data;
            this.index=startIndex;
        }

        public override bool CanRead {
            get { return true; }
        }

        public override bool CanSeek {
            get { return false; }
        }

        public override bool CanWrite {
            get { return false; }
        }

        public override void Flush() {
            throw new Exception("The method or operation is not implemented.");
        }

        public override long Length {
            get { return this.data.Length; }
        }

        public override long Position {
            get {
                return this.index;
            }
            set {
                this.index=value;
            }
        }

        public override int Read(byte[] buffer, int offset, int count) {
            //throw new Exception("The method or operation is not implemented.");
            if(index>=data.Length)
                return 0;//end of stream reached
            if(count<=0)
                return 0;

            if(data.Length<index+count)
                count=(int)(data.Length-index);
            if(buffer.Length<offset+count)
                count=buffer.Length-offset;
            Array.Copy(data, index, buffer, offset, count);
            index+=count;
            return count;
        }

        public override long Seek(long offset, System.IO.SeekOrigin origin) {
            throw new Exception("The method or operation is not implemented.");
        }

        public override void SetLength(long value) {
            throw new Exception("The method or operation is not implemented.");
        }

        public override void Write(byte[] buffer, int offset, int count) {
            throw new Exception("The method or operation is not implemented.");
        }
    }
}
