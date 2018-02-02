using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    class PartialFileAssembler : IDisposable {
        //private FileStreamAssembler.FileAssmeblyRootLocation fileAssemblyRootLocation;
        //private bool reassembleFileAtSourceHost;
        private FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation;
        //private bool tcpTransfer;
        //private System.Net.IPAddress sourceIp;
        //private System.Net.IPAddress destinationIp;
        //private NetworkHost sourceHost, destinationHost;
        //private ushort sourcePort;
        //private ushort destinationPort;
        private FiveTuple fiveTuple;
        private bool transferIsClientToServer;
        private FileStreamTypes fileStreamType;
        private string fileLocation;
        private string filename;
        private FileStreamAssemblerList parentAssemblerList;
        private string extendedFileId;
        private SortedList<long, ReconstructedFile> filePartList;
        private long totalFileSize;
        private bool closed = false;
        private DateTime timestamp;
        //private string originalLocation;
        private long initialFrameNumber;
        private string serverHostname;//host header in HTTP

        internal bool IsClosed { get { return this.closed; } }

        internal PartialFileAssembler(FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId, long totalFileSize, long initialFrameNumber, string serverHostname) {
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;
            /*
            this.tcpTransfer = tcpTransfer;
            this.sourceHost = sourceHost;
            this.destinationHost = destinationHost;
            this.sourcePort = sourcePort;
            this.destinationPort = destinationPort;
            */
            this.fiveTuple = fiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;
            this.fileStreamType = fileStreamType;
            this.fileLocation = fileLocation;
            this.filename = filename;
            this.parentAssemblerList = parentAssemblerList;
            this.extendedFileId = extendedFileId;
            this.totalFileSize = totalFileSize;
            //this.originalLocation = originalLocation;
            this.filePartList = new SortedList<long, ReconstructedFile>();
            this.initialFrameNumber = initialFrameNumber;
            this.serverHostname = serverHostname;
        }

        internal void AddFile(ReconstructedFile file, ContentRange range) {
            if (this.closed) {
                throw new Exception("The assembler is closed.");
            }
            else {
                this.timestamp = file.Timestamp;
                if (this.filePartList.ContainsKey(range.Start)) {
                    if (this.filePartList[range.Start].FileSize < file.FileSize)
                        this.filePartList[range.Start] = file;
                }
                else
                    this.filePartList.Add(range.Start, file);
            }
        }

        internal bool IsComplete() {
            //here comes the difficult part -- evaluating if we have all parts (may be overlapping).
            long nextOffset = 0;
            foreach (KeyValuePair<long, ReconstructedFile> offsetFile in this.filePartList) {
                if (offsetFile.Key > nextOffset)
                    break;
                else if (nextOffset < offsetFile.Key + offsetFile.Value.FileSize)
                    nextOffset = offsetFile.Key + offsetFile.Value.FileSize;
            }
            if (nextOffset >= this.totalFileSize)
                return true;
            else
                return false;
        }

        internal ReconstructedFile Reassemble() {

            string destinationPath = FileStreamAssembler.GetFilePath(this.fileAssmeblyRootLocation, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.fileLocation, this.filename, this.parentAssemblerList, this.extendedFileId);

            ReconstructedFile reconstructedFile = null;
            using (System.IO.FileStream fullFileStream = new System.IO.FileStream(destinationPath, System.IO.FileMode.Create, System.IO.FileAccess.Write, System.IO.FileShare.None, 256 * 1024)) {//256 kB buffer is probably a suitable value for good performance on large files
                foreach (KeyValuePair<long, ReconstructedFile> part in this.filePartList) {
                    //if (fullFileStream.Position != part.Key)
                    //    fullFileStream.Seek(part.Key, System.IO.SeekOrigin.Begin);
                    long partOffset = fullFileStream.Position - part.Key;
                    if(partOffset < part.Key + part.Value.FileSize)
                        using (System.IO.FileStream partStream = new System.IO.FileStream(part.Value.FilePath, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 256*1024)) {
                            if (partOffset > 0)
                                partStream.Seek(partOffset, System.IO.SeekOrigin.Begin);
                            //Stream.CopyTo isn't available in .NET 2.0 so I'll have to copy the data manually
                            byte[] buffer = new byte[4096];
                            int bytesRead = partStream.Read(buffer, 0, buffer.Length);
                            while(bytesRead > 0) {
                                fullFileStream.Write(buffer, 0, bytesRead);
                                bytesRead = partStream.Read(buffer, 0, buffer.Length);
                            }
                            
                        }
                }
                fullFileStream.Close();//so that I can read the full size of the file when creating the ReconstructedFile
                reconstructedFile = new ReconstructedFile(destinationPath, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.extendedFileId, this.initialFrameNumber, this.timestamp, this.serverHostname);
            }

            this.closed = true;
            this.filePartList.Clear();
            return reconstructedFile;
        }

        public void Dispose() {
            this.closed = true;
            this.filePartList.Clear();
        }
    }
}
