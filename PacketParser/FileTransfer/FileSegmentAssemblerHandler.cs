using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {

    /// <summary>
    /// Handles HTTP response headers such as "Content-Range: bytes 8621-23239/42941008"
    /// so that the partial downloads are merged into one file.
    /// </summary>
    class FileSegmentAssemblerHandler {

        //private string fileOutputDirectory;
        string fileOutputDirectory;//The "AssembledFiles" dir
        private FileTransfer.FileStreamAssemblerList fileStreamAssemblerList;
        private PopularityList<string, PacketParser.FileTransfer.FileSegmentAssembler> assemblerList;
        

        FileSegmentAssemblerHandler(string fileOutputDirectory, FileStreamAssemblerList fileStreamAssemblerList) {
            this.fileOutputDirectory = fileOutputDirectory;
            this.fileStreamAssemblerList = fileStreamAssemblerList;
            this.assemblerList = new PopularityList<string, FileSegmentAssembler>(100);//100 simultaneous partial downloads allowed
        }

        internal Add(ReconstructedFile reconstructedFile, ContentRange contentRange) {
            //reconstructedFile.se
            bool fileTransferIsServerToClient = true;
            new FileSegmentAssembler(this.fileOutputDirectory, fileTransferIsServerToClient, reconstructedFile.Filename, reconstructedFile.
        }
    }
}
