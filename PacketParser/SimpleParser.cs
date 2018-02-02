using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;

namespace PacketParser {

    [Guid("BBB92AA6-718C-4123-8187-F407D18600C0")]
    public interface ISimpleParser {

        [DispId(1)]
        void Parse(string pcapFileName);
    }

    [ComVisible(true)]
    [Guid("4544709D-BB0E-4f24-96F4-7A762996ACFA"), ClassInterface(ClassInterfaceType.AutoDual)]
    public class SimpleParser : ISimpleParser {

        

        public void Parse(string pcapFileName) {
            using (PcapFileHandler.PcapFileReader pcapReader = new PcapFileHandler.PcapFileReader(pcapFileName)) {
                ThreadStart threadStart = new ThreadStart(pcapReader.ThreadStart);
                Thread pcapReaderThread = new Thread(threadStart);
                //string exePath = System.IO.Path.GetFullPath(System.Windows.Forms.Application.ExecutablePath);
                //string executablePath = System.IO.Path.GetFullPath(System.Diagnostics.Process.GetCurrentProcess().MainModule.FileName);
                string executablePath = System.IO.Path.GetFullPath(System.Reflection.Assembly.GetEntryAssembly().Location);
                PacketParser.PacketHandler packetHandler = new PacketHandler(executablePath, System.Environment.CurrentDirectory, null, true);
                packetHandler.StartBackgroundThreads();

                int readFrames = 0;
                foreach (PcapFileHandler.PcapFrame packet in pcapReader.PacketEnumerator()) {

                    while (readFrames % (100) == 0 && packetHandler.FramesInQueue > 1000) {
                        System.Threading.Thread.Sleep(100);
                    }

                    PacketParser.Frame frame = packetHandler.GetFrame(packet.Timestamp, packet.Data, packet.DataLinkType);
                    packetHandler.AddFrameToFrameParsingQueue(frame);
                    readFrames++;
                }
            }
        }
    }
}
