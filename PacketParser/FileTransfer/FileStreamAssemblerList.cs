//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class FileStreamAssemblerList : PopularityList<string, FileStreamAssembler> {

        private const int QUEUE_SIZE = 100;

        private PacketHandler packetHandler;

        private bool decompressGzipStreams;
        //private string applicationExecutableDirectory;
        private string fileOutputDirectory;
        //private Dictionary<string, PartialFileAssembler> partialFileAssemblerDictionary;//handles Content-Range: bytes 21010-47021/47022
        PopularityList<string, PartialFileAssembler> partialFileAssemblerList;//handles Content-Range: bytes 21010-47021/47022
        private PopularityList<string, Queue<FileStreamAssembler>> fileStreamAssemblerQueue;

        internal bool DecompressGzipStreams { get { return this.decompressGzipStreams; } }
        //internal string FileOutputFolder { get { return applicationExecutableDirectory+"\\"+"assembledFiles"; } }
        internal string FileOutputDirectory { get { return fileOutputDirectory; } }
        internal PacketHandler PacketHandler { get { return packetHandler; } }
        //internal Dictionary<string, PartialFileAssembler> PartialFileAssemblerDictionary { get { return this.partialFileAssemblerDictionary; } }
        internal PopularityList<string, PartialFileAssembler> PartialFileAssemblerList { get { return this.partialFileAssemblerList; } }

        

        internal FileStreamAssemblerList(PacketHandler packetHandler, int maxPoolSize, string fileOutputDirectory)
            : base(maxPoolSize) {
            this.packetHandler = packetHandler;

            this.decompressGzipStreams=true;//this should be a setting that can be changed in an option-menu.
            
            //this.applicationExecutableDirectory=System.IO.Path.GetDirectoryName(applicationExecutableDirectory);
            this.fileOutputDirectory=System.IO.Path.GetDirectoryName(fileOutputDirectory);
            //this.masterFileSegmentAssembler = new FileSegmentAssembler(this.fileOutputDirectory, )
            //this.partialFileAssemblerDictionary = new Dictionary<string, PartialFileAssembler>();
            this.partialFileAssemblerList = new PopularityList<string, PartialFileAssembler>(QUEUE_SIZE);
            this.fileStreamAssemblerQueue = new PopularityList<string, Queue<FileStreamAssembler>>(QUEUE_SIZE);
        }

        private string GetAssemblerId(FileStreamAssembler assembler) {
            return GetAssemblerId(assembler.FiveTuple, assembler.TransferIsClientToServer, assembler.ExtendedFileId);
            //return GetAssemblerId(assembler.SourceHost, assembler.SourcePort, assembler.DestinationHost, assembler.DestinationPort, assembler.TcpTransfer, assembler.ExtendedFileId);
        }
        /*
        private string GetAssemblerId(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer) {
            return GetAssemblerId(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer, "");
        }
        private string GetAssemblerId(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, string extendedFileId) {
            return sourceHost.IPAddress.ToString()+sourcePort.ToString()+destinationHost.IPAddress.ToString()+destinationPort.ToString()+tcpTransfer.ToString()+extendedFileId;
        }
        */
        private string GetAssemblerId(FiveTuple fiveTuple, bool transferIsClientToServer, string extendedFileId = "") {
            return fiveTuple.ToString(transferIsClientToServer) + extendedFileId;
        }

        internal bool ContainsAssembler(FileStreamAssembler assembler) {
            string id=GetAssemblerId(assembler);
            return ContainsAssembler(id, false);
        }
        /*
        internal bool ContainsAssembler(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, bool assemblerIsAcive, FileStreamTypes fileStreamType){
            string id=GetAssemblerId(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer);
            return (base.ContainsKey(id) && base[id].FileStreamType==fileStreamType && base[id].IsActive==assemblerIsAcive);
        }
        */
        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, bool assemblerIsAcive, FileStreamTypes fileStreamType) {
            string id = GetAssemblerId(fiveTuple, transferIsClientToServer);
            return (base.ContainsKey(id) && base[id].FileStreamType == fileStreamType && base[id].IsActive == assemblerIsAcive);
        }
        /*
        internal bool ContainsAssembler(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer) {
            string id=GetAssemblerId(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer);
            return ContainsAssembler(id, false);
        }
        */
        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer) {
            string id = GetAssemblerId(fiveTuple, transferIsClientToServer);
            return ContainsAssembler(id, false);
        }
        /*
        internal bool ContainsAssembler(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, bool assemblerMustBeActive) {
            string id=GetAssemblerId(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer);
            return ContainsAssembler(id, assemblerMustBeActive);
        }*/
        internal bool ContainsAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, bool assemblerMustBeActive) {
            string id = GetAssemblerId(fiveTuple, transferIsClientToServer);
            return ContainsAssembler(id, assemblerMustBeActive);
        }

        private bool ContainsAssembler(string assemblerId, bool assemblerMustBeActive) {
            return (base.ContainsKey(assemblerId) && (!assemblerMustBeActive || base[assemblerId].IsActive));
        }


        internal void Remove(FileStreamAssembler assembler, bool closeAssembler) {
            string id=GetAssemblerId(assembler);
            if(base.ContainsKey(id))
                base.Remove(id);
            if(closeAssembler)//it should sometimes be closed elsewhere
                assembler.Clear();
            if (this.fileStreamAssemblerQueue.ContainsKey(id) && this.fileStreamAssemblerQueue[id].Count > 0)
                base.Add(id, this.fileStreamAssemblerQueue[id].Dequeue());
        }

        
        /*
        internal FileStreamAssembler GetAssembler(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer) {
            //Changed 2011-04-18
            return this.GetAssembler(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer, "");
        }
        //Changed 2011-04-18
        internal FileStreamAssembler GetAssembler(NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, string extendedFileId) {
            string id=GetAssemblerId(sourceHost, sourcePort, destinationHost, destinationPort, tcpTransfer, extendedFileId);
            return base[id];
        }
        */
        internal FileStreamAssembler GetAssembler(FiveTuple fiveTuple, bool transferIsClientToServer, string extendedFileId = null) {
            string id = GetAssemblerId(fiveTuple, transferIsClientToServer, extendedFileId);
            return base[id];
        }

        internal IEnumerable<FileStreamAssembler> GetAssemblers(NetworkHost sourceHost, NetworkHost destinationHost, FileStreamTypes fileStreamType, bool isActive){
            foreach(FileStreamAssembler assembler in base.GetValueEnumerator()) {
                if(assembler.IsActive==isActive && assembler.SourceHost==sourceHost && assembler.DestinationHost==destinationHost && assembler.FileStreamType==fileStreamType)
                    yield return assembler;
            }
            yield break;
        }

        internal void AddOrEnqueue(FileStreamAssembler assembler) {
            string id = GetAssemblerId(assembler);
            if (this.ContainsAssembler(id, false)) {
                if (this.fileStreamAssemblerQueue.ContainsKey(id))
                    this.fileStreamAssemblerQueue[id].Enqueue(assembler);
                else {
                    Queue<FileStreamAssembler> q = new Queue<FileStreamAssembler>();
                    q.Enqueue(assembler);
                    this.fileStreamAssemblerQueue.Add(id, q);
                }
            }
            else this.Add(assembler);
        }

        internal void Add(FileStreamAssembler assembler) {
            string id=GetAssemblerId(assembler);

            base.Add(id, assembler);
        }

        //Removes all data and stored files
        internal void ClearAll() {

            foreach(FileStreamAssembler assembler in base.GetValueEnumerator())
                assembler.Clear();
            base.Clear();

            this.partialFileAssemblerList.Clear();
            this.fileStreamAssemblerQueue.Clear();

            //remove all files
            foreach (string subDirectory in System.IO.Directory.GetDirectories(this.FileOutputDirectory))
                if(subDirectory==this.FileOutputDirectory+ System.IO.Path.DirectorySeparatorChar +"cache")
                    foreach(string cacheFile in System.IO.Directory.GetFiles(subDirectory))
                        try {
                            System.IO.File.Delete(cacheFile);
                        }
                        catch {

                            packetHandler.OnAnomalyDetected("Error deleting file \""+cacheFile+"\"");
                        }

                else
                    try {
                        System.IO.Directory.Delete(subDirectory, true);
                    }
                    catch(Exception e) {
                        packetHandler.OnAnomalyDetected("Error deleting directory \""+subDirectory+"\"");
                    }
        }
    }
}
