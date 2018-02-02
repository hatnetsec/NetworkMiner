using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public interface IPcapStreamReader {
        //public bool AbortReadingPcapStream();
        long Position { get; }

        byte[] BlockingRead(int bytesToRead);

        int BlockingRead(byte[] buffer, int offset, int count);

    }
}
