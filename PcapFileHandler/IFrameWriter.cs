using System;
using System.Collections.Generic;
using System.Text;

namespace PcapFileHandler {
    public interface IFrameWriter : IDisposable {

        bool IsOpen { get; }
        string Filename { get; }
        bool OutputIsPcapNg { get; }

        void WriteFrame(PcapFrame frame);
        void WriteFrame(PcapFrame frame, bool flush);
        void WriteFrame(byte[] rawFrameHeaderBytes, byte[] rawFrameDataBytes, bool littleEndian);
        
        void Close();
    }
}
