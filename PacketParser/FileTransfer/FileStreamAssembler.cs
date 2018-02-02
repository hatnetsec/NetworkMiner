//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    

    public class FileStreamAssembler : IDisposable{

        public delegate void FileReconsructedEventHandler(string extendedFileId, ReconstructedFile file);

        public event FileReconsructedEventHandler FileReconstructed;


        public const string ASSMEBLED_FILES_DIRECTORY = "AssembledFiles";

        //Applications: “.exe”, “.pif”, “.application”, “.gadget”, “.msi”, “.msp”, “.com”, “.scr”, “.hta”, “.cpl”, “.msc”, “.jar”
        //Scripts: “.bat”, “.cmd”, “.vb”, “.vbs”, “.vbe”, “.js”, “.jse”, “.ws”, “.wsf”, “.wsc”, “.wsh”,
        //         “.ps1”, “.ps1xml”, “.ps2”, “.ps2xml”, “.psc1”, “.psc2”, “.msh”, “.msh1”, “.msh2”, “.mshxml”, “.msh1xml”, “.msh2xml”
        //good source: http://www.howtogeek.com/137270/50-file-extensions-that-are-potentially-dangerous-on-windows/
        //another source: https://circl.lu/pub/tr-41/#proactive-measures-for-the-wannacry-ransomware
        internal static readonly string[] executableExtensions = {
            "exe", "bat", "msi", "vb", "vbe", "vbs", "pif", "com", "scr", "jar", "cmd", "js", "jse",
            "ps1", "psc1", "application", "gadget", "msp", "hta", "cpl", "msc",
            "ws", "wsf", "wsc", "wsh", "ps1xml", "ps2", "ps2xml", "psc1", "psc2", "msh", "msh1", "msh2", "mshxml", "msh1xml", "msh2xml"
        };

        public enum FileAssmeblyRootLocation { cache, source, destination };

        /**
         * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
         * 
         * The following reserved characters:
         *     < (less than)
         *     > (greater than)
         *     : (colon)
         *     " (double quote)
         *     / (forward slash)
         *     \ (backslash)
         *     | (vertical bar or pipe)
         *     ? (question mark)
         *     * (asterisk)
         *     
         *     Do not use the following reserved names for the name of a file:
         *     CON, PRN, AUX, NUL, COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
         *     LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
         **/


        private static char[] specialCharacters={ ':', '*', '?', '"', '<', '>', '|' };
        private static char[] directorySeparators={ '\\', '/' };
        private static string[] forbiddenNames = { "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9" };

        private FileStreamAssemblerList parentAssemblerList;
        //private NetworkHost sourceHost, destinationHost;
        //private ushort sourcePort, destinationPort;
        //private bool tcpTransfer;
        private FiveTuple fiveTuple;
        private bool transferIsClientToServer;

        private FileStreamTypes fileStreamType;
        private Packets.HttpPacket.ContentEncodings contentEncoding;
        private string filename, fileLocation;
        private long fileContentLength;//in bytes
        private long fileSegmentRemainingBytes;//the length (in bytes) of the current file segment to recieve
        private string details;
        private string extendedFileId;
        //private bool reassembleFileAtSourceHost;
        private FileAssmeblyRootLocation fileAssmeblyRootLocation;
        private string serverHostname;//host header in HTTP

        private int assembledByteCount;
        private System.IO.FileStream fileStream;
        private SortedList<uint, byte[]> tcpPacketBufferWindow;

        private bool isActive;

        private long initialFrameNumber;
        private DateTime timestamp;
        private ContentRange contentRange;

        internal NetworkHost SourceHost { get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ClientHost;
                else
                    return this.fiveTuple.ServerHost;
            }
        }
        internal NetworkHost DestinationHost { get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ServerHost;
                else
                    return this.fiveTuple.ClientHost;
            }
        }
        internal ushort SourcePort { get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ClientPort;
                else

                    return this.fiveTuple.ServerPort;
            }
        }
        internal ushort DestinationPort { get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ServerPort;
                else
                    return this.fiveTuple.ClientPort;
            }
        }
        internal string Filename {
            get { return filename; }
            set {
                filename =value;
                if(this.fileLocation != null && this.fileLocation.Length > 0 && this.filename != null)
                    FixFilenameAndLocation(ref this.filename, ref this.fileLocation);
            }
        }
        internal string FileLocation { get { return this.fileLocation; } }
        internal string Details { get { return this.details; } }
        //internal bool TcpTransfer { get { return tcpTransfer; } }
        internal FiveTuple FiveTuple { get { return this.fiveTuple; } }
        internal bool TransferIsClientToServer { get { return this.transferIsClientToServer; } }
        internal long FileContentLength {
            get { return fileContentLength; }
            set { this.fileContentLength=value; }
        }
        internal long FileSegmentRemainingBytes { get { return fileSegmentRemainingBytes; } set { this.fileSegmentRemainingBytes=value; } }
        internal int AssembledByteCount { get { return this.assembledByteCount; } }
        internal FileStreamTypes FileStreamType { get { return fileStreamType; } set { this.fileStreamType=value; } }
        internal Packets.HttpPacket.ContentEncodings ContentEncoding {
            get { return this.contentEncoding; }
            set {
                this.contentEncoding=value;
                if(!this.parentAssemblerList.DecompressGzipStreams && !this.filename.EndsWith(".gz"))
                    this.filename=this.filename+".gz";
            }
        }
        internal bool IsActive { get { return this.isActive; } }
        internal string ExtendedFileId {
            get {
                if(this.extendedFileId==null)
                    return string.Empty;
                else
                    return this.extendedFileId;
            }
            set { this.extendedFileId=value; }
        }

        //bool reassembleFileAtSourceHost
        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, long initialFrameNumber, DateTime timestamp, string serverHostname = null)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, null, initialFrameNumber, timestamp, FileAssmeblyRootLocation.source, serverHostname) {
        }
        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, long initialFrameNumber, DateTime timestamp, FileAssmeblyRootLocation fileAssmeblyRootLocation)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, null, initialFrameNumber, timestamp, fileAssmeblyRootLocation) {
        }

        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp)
            :
            this(parentAssemblerList, fiveTuple, transferIsClientToServer, fileStreamType, filename, fileLocation, 0, 0, details, extendedFileId, initialFrameNumber, timestamp, FileAssmeblyRootLocation.source) {
        }

        internal ContentRange ContentRange {
            set { this.contentRange = value; }
            get { return this.contentRange; }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="sourceHost"></param>
        /// <param name="sourcePort"></param>
        /// <param name="destinationHost"></param>
        /// <param name="destinationPort"></param>
        /// <param name="tcpTransfer">True=TCP, False=UDP</param>
        /// <param name="fileStreamType"></param>
        /// <param name="filename">for example "image.gif"</param>
        /// <param name="fileLocation">for example "/images", empty string for root folder</param>
        //internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, NetworkHost sourceHost, ushort sourcePort, NetworkHost destinationHost, ushort destinationPort, bool tcpTransfer, FileStreamTypes fileStreamType, string filename, string fileLocation, long fileContentLength, long fileSegmentRemainingBytes, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp, bool reassembleFileAtSourceHost, string serverHostname = null){
        internal FileStreamAssembler(FileStreamAssemblerList parentAssemblerList, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string filename, string fileLocation, long fileContentLength, long fileSegmentRemainingBytes, string details, string extendedFileId, long initialFrameNumber, DateTime timestamp, FileAssmeblyRootLocation fileAssmeblyRootLocation, string serverHostname = null) {
            this.parentAssemblerList=parentAssemblerList;
            this.fiveTuple = fiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;
            /*
            this.sourceHost=sourceHost;
            this.sourcePort=sourcePort;
            this.destinationHost=destinationHost;
            this.destinationPort=destinationPort;
            this.tcpTransfer=tcpTransfer;
            */
            this.fileStreamType=fileStreamType;
            this.fileContentLength=fileContentLength;//this one can not be set already when the client requests the file...so it has to be changed later
            this.fileSegmentRemainingBytes=fileSegmentRemainingBytes;
            this.details=details;
            this.contentEncoding=Packets.HttpPacket.ContentEncodings.Identity;//default
            this.isActive=false;
            this.extendedFileId=extendedFileId;
            this.initialFrameNumber=initialFrameNumber;
            this.timestamp=timestamp;

            this.filename=filename;
            this.fileLocation=fileLocation;
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;

            //this.reassembleFileAtSourceHost = reassembleFileAtSourceHost;

            this.serverHostname = serverHostname;
            


            //Sigh I just hate the limitation on file and folder length.
            //See: http://msdn2.microsoft.com/en-us/library/aa365247.aspx
            //Or: http://blogs.msdn.com/bclteam/archive/2007/02/13/long-paths-in-net-part-1-of-3-kim-hamilton.aspx

            //see if there is any fileLocation info in the filename and move it to the fileLocation
            FixFilenameAndLocation(ref this.filename, ref this.fileLocation);

            

            this.assembledByteCount=0;
            this.tcpPacketBufferWindow=new SortedList<uint, byte[]>();

            if (isActive) {
                try {
                    this.fileStream = new System.IO.FileStream(GetFilePath(FileAssmeblyRootLocation.cache), System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite);
                }
                catch (System.UnauthorizedAccessException) {//System.IO.__Error.WinIOError
                    this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(GetFilePath(FileAssmeblyRootLocation.cache));
                }
            }
            else
                this.fileStream = null;
        }

        public static string UrlEncode(string s) {
            return System.Web.HttpUtility.UrlEncode(s);
        }

        internal static void FixFilenameAndLocation(ref string filename, ref string fileLocation){
            if(filename.Contains("/")) {
                fileLocation=filename.Substring(0, filename.LastIndexOf('/')+1);
                filename=filename.Substring(filename.LastIndexOf('/')+1);
            }
            if(filename.Contains("\\")) {
                fileLocation=filename.Substring(0, filename.LastIndexOf('\\')+1);
                filename=filename.Substring(filename.LastIndexOf('\\')+1);
            }

            filename=System.Web.HttpUtility.UrlDecode(filename);
            while(filename.IndexOfAny(specialCharacters)>-1)
                filename=filename.Remove(filename.IndexOfAny(specialCharacters), 1);
            while(filename.IndexOfAny(directorySeparators)>-1)
                filename=filename.Remove(filename.IndexOfAny(directorySeparators), 1);
            while(filename.StartsWith("."))
                filename=filename.Substring(1);
            if(filename.Length>32) {//not allowed by Windows to be more than 260 characters
                //I want to make sure I keep the extension when the filename is cut...
                int extensionPosition=filename.LastIndexOf('.');
                if(extensionPosition<0 || extensionPosition<=filename.Length-20)
                    filename=filename.Substring(0, 20);
                else
                    filename=filename.Substring(0, 20-filename.Length+extensionPosition)+filename.Substring(extensionPosition);
            }

            fileLocation=System.Web.HttpUtility.UrlDecode(fileLocation);
            fileLocation = fileLocation.Replace("..", "_");
            
            //this.fileLocation=System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(this.fileLocation));
            fileLocation =fileLocation.Replace('\\', '/');//I prefer using frontslash
            

            while (fileLocation.IndexOfAny(specialCharacters)>-1)
                fileLocation=fileLocation.Remove(fileLocation.IndexOfAny(specialCharacters), 1);
            if(fileLocation.Length>0 && !fileLocation.StartsWith("/"))
                fileLocation="/"+fileLocation;
            foreach(string forbiddenName in forbiddenNames) {
                int index = fileLocation.IndexOf("/" + forbiddenName + "/", StringComparison.InvariantCultureIgnoreCase);
                if (index >= 0)
                    fileLocation = fileLocation.Substring(0, index + 1) + "_" + fileLocation.Substring(index + 1);
            }
            fileLocation = fileLocation.Replace("/./", "/");//replace "/dir/./sub/" with "/dir/sub"
            while (fileLocation.EndsWith("."))
                fileLocation = fileLocation.Substring(0, fileLocation.Length - 1);
            //char[] directorySeparators={'/','\\'};
            fileLocation =fileLocation.TrimEnd(directorySeparators);
            if(fileLocation.Length>40)//248 characters totally (directory + file name) is the maximum allowed
                fileLocation=fileLocation.Substring(0, 40).TrimEnd(directorySeparators);
        }

        internal bool TryActivate() {
            try {
                if(this.fileStream==null) {
                    this.fileStream=new System.IO.FileStream(GetFilePath(FileAssmeblyRootLocation.cache), System.IO.FileMode.Create, System.IO.FileAccess.ReadWrite);
                }
                this.isActive=true;
                return true;
            }
            catch(System.UnauthorizedAccessException ex) {//System.IO.__Error.WinIOError
                this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(GetFilePath(FileAssmeblyRootLocation.cache));
                //this.parentAssemblerList.PacketHandler.OnAnomalyDetected("User does not have write permissions to " + GetFilePath(FileAssmeblyRootLocation.cache));

                return false;
            }
            catch(Exception ex) {
                this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Unable to create output stream for " + this.fileLocation);
                return false;
            }
        }

        private void PacketHandler_InsufficientWritePermissionsDetected(string obj) {
            throw new NotImplementedException();
        }

        /*
        internal void DoTheSwitcheroo() {
            
            this.reassembleFileAtSourceHost = !this.reassembleFileAtSourceHost;
            NetworkHost oldSourceHost = this.sourceHost;
            ushort oldSourcePort = this.sourcePort;
            this.sourceHost = this.destinationHost;
            this.sourcePort = this.destinationPort;
            this.destinationHost = oldSourceHost;
            this.destinationPort = oldSourcePort;
            
    }*/


        private string GetFilePath(FileAssmeblyRootLocation fileAssemblyRootLocation) {
            return GetFilePath(fileAssemblyRootLocation, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.fileLocation, this.filename, this.parentAssemblerList, this.ExtendedFileId);
        }

        //internal static string GetFilePath(bool tempCachePath, bool tcpTransfer, System.Net.IPAddress sourceIp, System.Net.IPAddress destinationIp, ushort sourcePort, ushort destinationPort, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId) {
        internal static string GetFilePath(FileAssmeblyRootLocation fileAssemblyRootLocation, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string fileLocation, string filename, FileStreamAssemblerList parentAssemblerList, string extendedFileId) {
            //sanitize filename
            if (filename.IndexOfAny(System.IO.Path.GetInvalidFileNameChars()) >= 0) {
                foreach(char c in System.IO.Path.GetInvalidFileNameChars())
                    filename.Replace(c, '_');
            }
            if(parentAssemblerList.PacketHandler.DefangExecutableFiles) {
                
                foreach (string ext in executableExtensions)
                    if (filename.EndsWith("." + ext))
                        filename = filename + "_";//defanged by adding "_" after the extension
            }

            //sanitize file location
            fileLocation = fileLocation.Replace("..", "_");//just to ensure that no file is written to a parent directory
            fileLocation = fileLocation.Replace("/./", "/").Replace("\\.\\", "\\");//replace "/dir/./sub/" with "/dir/sub"
            while (fileLocation.EndsWith("."))
                fileLocation = fileLocation.Substring(0, fileLocation.Length - 1);

            if (fileLocation.IndexOfAny(System.IO.Path.GetInvalidPathChars()) >= 0) {
                foreach (char c in System.IO.Path.GetInvalidPathChars())
                    fileLocation.Replace(c, '_');
            }

            string filePath;
            string protocolString;
            if(fileStreamType==FileStreamTypes.HttpGetNormal || fileStreamType==FileStreamTypes.HttpGetChunked)
                protocolString="HTTP";
            else if(fileStreamType==FileStreamTypes.SMB)
                protocolString="SMB";
            else if (fileStreamType == FileStreamTypes.SMB2)
                protocolString = "SMB2";
            else if(fileStreamType==FileStreamTypes.TFTP)
                protocolString="TFTP";
            else if(fileStreamType==FileStreamTypes.TlsCertificate)
                protocolString="TLS_Cert";
            else if(fileStreamType==FileStreamTypes.FTP)
                protocolString="FTP";
            else if(fileStreamType==FileStreamTypes.HttpPostMimeMultipartFormData)
                protocolString="MIME_form-data";
            else if(fileStreamType==FileStreamTypes.HttpPostMimeFileData)
                protocolString="MIME_file-data";
            else if(fileStreamType==FileStreamTypes.OscarFileTransfer)
                protocolString="OSCAR";
            else if (fileStreamType == FileStreamTypes.POP3)
                protocolString = "POP3";
            else if(fileStreamType==FileStreamTypes.SMTP)
                protocolString="SMTP";
            else if (fileStreamType == FileStreamTypes.IMAP)
                protocolString = "IMAP";
            else
                throw new Exception("Not implemented yet");

            string transportString = fiveTuple.Transport.ToString();
            /*
            if (tcpTransfer)
                transportString="TCP";
            else
                transportString="UDP";
                */
            System.Net.IPAddress sourceIp, destinationIp;
            ushort sourcePort, destinationPort;
            if(transferIsClientToServer) {
                sourceIp = fiveTuple.ClientHost.IPAddress;
                sourcePort = fiveTuple.ClientPort;
                destinationIp = fiveTuple.ServerHost.IPAddress;
                destinationPort = fiveTuple.ServerPort;
            }
            else {
                destinationIp = fiveTuple.ClientHost.IPAddress;
                destinationPort = fiveTuple.ClientPort;
                sourceIp = fiveTuple.ServerHost.IPAddress;
                sourcePort = fiveTuple.ServerPort;
            }

            if (fileAssemblyRootLocation == FileAssmeblyRootLocation.cache) {
                extendedFileId = Utils.StringManglerUtil.ConvertToFilename(extendedFileId, 10);//truncate to 10 valid filename chars
                filePath = "cache/" + sourceIp.ToString().Replace(':', '-') + "_" + transportString + sourcePort.ToString() + "-" + destinationIp.ToString().Replace(':', '-') + "_" + transportString + destinationPort.ToString() + "_" + protocolString + extendedFileId + ".txt";//with extendedFileId 2011-04-18
                //filePath = "cache/" + sourceIp.ToString().Replace(':', '-') + "_" + transportString + sourcePort.ToString() + " - " + destinationIp.ToString().Replace(':', '-') + "_" + transportString + destinationPort.ToString() + "_" + protocolString + ".txt";//without extendedFileId
            }
            else {
                //this one generates directories like: "/HTTP - TCP 80/<directory>/<filename>"
                //filePath=sourceIp.ToString().Replace(':', '-')+"/"+protocolString+" - "+transportString+" "+sourcePort.ToString()+fileLocation+"/"+filename;
                //this one generates directories like: "/TCP-80/<directory>/<filename>"
                if(fileAssemblyRootLocation == FileAssmeblyRootLocation.source)
                    filePath=sourceIp.ToString().Replace(':', '-')+"/"+transportString+"-"+sourcePort.ToString()+fileLocation+"/"+filename;
                else
                    filePath = destinationIp.ToString().Replace(':', '-') + "/" + transportString + "-" + destinationPort.ToString() + fileLocation + "/" + filename;
                try {
                    System.IO.Path.GetDirectoryName(filePath);
                }
                catch {
                    //something could be wrong with the path.. so let's replace it with something that should work better
                    //Examples of things that can go wrong is that the file or directory has a reserved name (like COM2, CON or LPT1) as shown here:
                    //http://www.ureader.com/msg/144639432.aspx
                    //http://msdn.microsoft.com/en-us/library/aa365247(VS.85).aspx
                    //this one generates directories like: "/HTTP - TCP 80/<directory>/<filename>"
                    //filePath=sourceIp.ToString().Replace(':', '-')+"/"+protocolString+" - "+transportString+" "+sourcePort.ToString()+"/"+System.IO.Path.GetRandomFileName();
                    //this one generates directories like: "/TCP-80/<directory>/<filename>"
                    filePath=sourceIp.ToString().Replace(':', '-')+"/"+transportString+"-"+sourcePort.ToString()+"/"+System.IO.Path.GetRandomFileName();
                }
            }

            
            //filePath=System.IO.Path.GetDirectoryName(parentAssemblerList.FileOutputFolder)+"\\"+filePath;
            filePath = parentAssemblerList.FileOutputDirectory + System.IO.Path.DirectorySeparatorChar + filePath;

            if (System.IO.Path.DirectorySeparatorChar != '/' && filePath.Contains("/"))
                filePath = filePath.Replace('/', System.IO.Path.DirectorySeparatorChar);
            /*if(filePath.Length>=248)
                filePath="\\\\?\\"+filePath;*/

            if(fileAssemblyRootLocation != FileAssmeblyRootLocation.cache && System.IO.File.Exists(filePath)) {

                //change filename to avoid overwriting previous files
                int iterator=1;
                string filePathPrefix;
                string filePathSuffix;//including the "." as in ".txt"
                //now, find the breakpoint in filePath where "[1]" should be inserted
                int extentionPosition=filePath.LastIndexOf('.');//The index position of value if that character is found, or -1 if it is not
                int filenamePosition = filePath.LastIndexOf(System.IO.Path.DirectorySeparatorChar);

                if(extentionPosition<0) {
                    filePathPrefix=filePath;
                    filePathSuffix="";
                }
                else if(extentionPosition>filenamePosition) {
                    filePathPrefix=filePath.Substring(0, extentionPosition);
                    filePathSuffix=filePath.Substring(extentionPosition);
                }
                else {
                    filePathPrefix=filePath;
                    filePathSuffix="";
                }

                string uniqueFilePath=filePathPrefix+"["+iterator+"]"+filePathSuffix;
                while(System.IO.File.Exists(uniqueFilePath)) {
                    iterator++;
                    uniqueFilePath=filePathPrefix+"["+iterator+"]"+filePathSuffix;
                }
                filePath=uniqueFilePath;
            }

            return filePath;
        }

        internal void SetRemainingBytesInFile(int remainingByteCount) {
            this.fileContentLength=assembledByteCount+remainingByteCount;
        }

        internal void AddData(Packets.TcpPacket tcpPacket) {
            if(this.fiveTuple.Transport != FiveTuple.TransportProtocol.TCP)
                throw new Exception("No TCP packets accepted, only " + this.fiveTuple.Transport.ToString());
            if(tcpPacket.PayloadDataLength>0)
                AddData(tcpPacket.GetTcpPacketPayloadData(), tcpPacket.SequenceNumber);
        }

        internal void AddData(byte[] packetData, ushort packetNumber) {
            AddData(packetData, (uint)packetNumber);
        }
        internal void AddData(byte[] packetData, uint tcpPacketSequenceNumber){

            if(!this.isActive) {
                throw new Exception("FileStreamAssembler has not been activated prior to adding data!");
            }
            else {

                if(packetData.Length<=0)
                    return;//don't do anything with empty packets...
                if(tcpPacketBufferWindow.ContainsKey(tcpPacketSequenceNumber))
                    return;//we already have the packet (I'm not putting any effort into seeing if they are different and which one is correct)
                if(this.FileStreamType!=FileStreamTypes.HttpGetChunked && this.FileStreamType!=FileStreamTypes.TFTP && this.FileContentLength!=-1) {
                    if(fileSegmentRemainingBytes<packetData.Length) {
                        //throw new Exception("Assembler is only expecting data segment length up to "+fileSegmentRemainingBytes+" bytes");
                        this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Assembler is only expecting data segment length up to "+fileSegmentRemainingBytes+" bytes");
                        return;
                    }
                    fileSegmentRemainingBytes-=packetData.Length;
                }
                tcpPacketBufferWindow.Add(tcpPacketSequenceNumber, packetData);
                this.assembledByteCount+=packetData.Length;


                //in order to improve performance I could ofcourse have a separate thread doing all the file operations
                //I'll just simply set the maximum TCP packets stored to 64, this can be adjusted to improve performance.
                //A smaller number gives better performance (both memory and CPU wise) while a larger number gives better tolerance to out-of-order (i.e. non-sequential) TCP packets

                //If this valus is changed, then also make sure to revise "dataListMaxSize" in NetworkTcpSession.TcpDataStream and possibly also "maxPacketFragments" in NetworkTcpSession.VirtualTcpData.TryAppendNextPacket()
                while(tcpPacketBufferWindow.Count>64) {
                    uint key=tcpPacketBufferWindow.Keys[0];
                    this.fileStream.Write(tcpPacketBufferWindow[key], 0, tcpPacketBufferWindow[key].Length);
                    tcpPacketBufferWindow.Remove(key);
                }

                if((this.FileStreamType==FileStreamTypes.HttpGetNormal
                    /*|| this.FileStreamType==FileStreamTypes.SMB*/
                    || this.FileStreamType == FileStreamTypes.IMAP
                    || this.FileStreamType == FileStreamTypes.POP3
                    || this.FileStreamType==FileStreamTypes.SMTP
                    || this.fileStreamType==FileStreamTypes.TlsCertificate
                    || this.fileStreamType==FileStreamTypes.FTP
                    || this.fileStreamType==FileStreamTypes.HttpPostMimeMultipartFormData
                    || this.fileStreamType==FileStreamTypes.HttpPostMimeFileData
                    || this.fileStreamType==FileStreamTypes.OscarFileTransfer)
                    && assembledByteCount>=fileContentLength && fileContentLength!=-1) {//we have received the whole file
                    FinishAssembling();
                }
                else if(this.FileStreamType!=FileStreamTypes.HttpGetChunked && this.FileStreamType!=FileStreamTypes.TFTP && FileSegmentRemainingBytes==0) {
                    this.isActive=false;//deactivate (only for SMB?)
                }
                else if(this.FileStreamType==FileStreamTypes.HttpGetChunked) {
                    byte[] chunkTrailer={ 0x30, 0x0d, 0x0a, 0x0d, 0x0a };//see: RFC 2616 3.6.1 Chunked Transfer Coding
                    if(packetData.Length>=chunkTrailer.Length) {
                        bool packetDataHasChunkTrailer=true;
                        for(int i=0; i<chunkTrailer.Length && packetDataHasChunkTrailer; i++)
                            if(packetData[packetData.Length-chunkTrailer.Length+i]!=chunkTrailer[i])
                                packetDataHasChunkTrailer=false;
                        if(packetDataHasChunkTrailer)
                            FinishAssembling();

                    }

                }
            }
        }




        /// <summary>
        /// Closes the fileStream and removes the FileStreamAssembler from the parentAssemblerList
        /// </summary>
        internal void FinishAssembling() {


            this.isActive = false;
            if (this.fileStream != null) {
                try {
                    foreach (byte[] data in tcpPacketBufferWindow.Values)
                        this.fileStream.Write(data, 0, data.Length);
                    this.fileStream.Flush();
                }
                catch (Exception ex) {
                    if (fileStream != null)
                        parentAssemblerList.PacketHandler.OnAnomalyDetected("Error writing final data to file \"" + fileStream.Name + "\".\n" + ex.Message);
                    else
                        parentAssemblerList.PacketHandler.OnAnomalyDetected("Error writing final data to file \"" + this.filename + "\".\n" + ex.Message);
                }
            }
            tcpPacketBufferWindow.Clear();
            parentAssemblerList.Remove(this, false);

            string destinationPath = GetFilePath(this.fileAssmeblyRootLocation);
            /*
            if (this.reassembleFileAtSourceHost)
                destinationPath = GetFilePath(FileAssmeblyRootLocation.source);
            else
                destinationPath = GetFilePath(FileAssmeblyRootLocation.destination);
                */

            //this.filename might now be "index.html" but destinationPath might end with "index.html[1]"
            //I need to create the directory here since the file might either be moved to this located or a new file will be created there from a stream
            //string directoryName = destinationPath.Substring(0, destinationPath.Length - this.filename.Length);
            string directoryName = System.IO.Path.GetDirectoryName(destinationPath);
            //string directoryName = destinationPath.Substring(0, destinationPath.Length - System.IO.Path.GetFileName(destinationPath).Length);

            if (this.fileStreamType != FileStreamTypes.HttpPostMimeMultipartFormData && !System.IO.Directory.Exists(directoryName)) {
                if (System.IO.File.Exists(directoryName)) {
                    parentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating directory \"" + directoryName + "\" because a file with the same name already exists. Full path was : " + destinationPath);

                }
                else {
                    try {
                        System.IO.Directory.CreateDirectory(directoryName);
                    }
                    catch (Exception e) {
                        parentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating directory \"" + directoryName + "\" for file : " + destinationPath+".\n" + e.Message);
                    }
                }
            }
            if(System.IO.File.Exists(destinationPath))
                try {
                    System.IO.File.Delete(destinationPath);
                }
                catch(Exception e) {
                    parentAssemblerList.PacketHandler.OnAnomalyDetected("Error deleting file \""+destinationPath+"\" (tried to replace it)");
                    //parentAssemblerList.PacketHandler.ParentForm.ShowError("Error deleting file \""+destinationPath+"\" (tried to replace it)");
                }

            //do some special fixes such as un-chunk data or decompress compressed data
            if(this.fileStreamType==FileStreamTypes.HttpGetChunked || (parentAssemblerList.DecompressGzipStreams && this.contentEncoding==Packets.HttpPacket.ContentEncodings.Gzip) || this.contentEncoding==Packets.HttpPacket.ContentEncodings.Deflate) {
                this.fileStream.Position=0;//move to fileStream start since it needs to be read

                if(this.fileStreamType==FileStreamTypes.HttpGetChunked && (parentAssemblerList.DecompressGzipStreams && this.contentEncoding==Packets.HttpPacket.ContentEncodings.Gzip)) {
                    using(DeChunkedDataStream deChunkedStream=new DeChunkedDataStream(this.fileStream)) {
                        using(System.IO.Compression.GZipStream decompressedStream=new System.IO.Compression.GZipStream(deChunkedStream, System.IO.Compression.CompressionMode.Decompress)) {
                            try {
                                this.WriteStreamToFile(decompressedStream, destinationPath);
                            }
                            catch (System.UnauthorizedAccessException) {
                                this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                            }
                            catch (Exception e) {
                                this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                                //this.parentAssemblerList.PacketHandler.ParentForm.ShowError("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                            }
                            decompressedStream.Close();
                        }
                        deChunkedStream.Close();
                    }
                }
                else if(this.fileStreamType==FileStreamTypes.HttpGetChunked && this.contentEncoding==Packets.HttpPacket.ContentEncodings.Deflate) {
                    using(DeChunkedDataStream deChunkedStream=new DeChunkedDataStream(this.fileStream)) {
                        using(System.IO.Compression.DeflateStream decompressedStream=new System.IO.Compression.DeflateStream(deChunkedStream, System.IO.Compression.CompressionMode.Decompress)) {
                            try {
                                this.WriteStreamToFile(decompressedStream, destinationPath);
                            }
                            catch (System.UnauthorizedAccessException) {
                                this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                            }
                            catch (Exception e) {
                                this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                                //this.parentAssemblerList.PacketHandler.ParentForm.ShowError("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                            }
                            
                            decompressedStream.Close();
                        }
                        deChunkedStream.Close();
                    }
                }
                else if(this.fileStreamType==FileStreamTypes.HttpGetChunked) {
                    using(DeChunkedDataStream deChunkedStream=new DeChunkedDataStream(this.fileStream)) {
                        try {
                            this.WriteStreamToFile(deChunkedStream, destinationPath);
                        }
                        catch (System.UnauthorizedAccessException) {
                            this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                        }
                        catch (Exception e) {
                            this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                            //this.parentAssemblerList.PacketHandler.ParentForm.ShowError("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                        }
                        deChunkedStream.Close();
                    }
                }
                else {
                    using(System.IO.Compression.GZipStream decompressedStream=new System.IO.Compression.GZipStream(this.fileStream, System.IO.Compression.CompressionMode.Decompress)) {
                        try {
                            this.WriteStreamToFile(decompressedStream, destinationPath);
                        }
                        catch (System.UnauthorizedAccessException) {
                            this.parentAssemblerList.PacketHandler.OnInsufficientWritePermissionsDetected(destinationPath);
                        }
                        catch (Exception e) {
                            this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                            //this.parentAssemblerList.PacketHandler.ParentForm.ShowError("Error: Cannot write to file "+destinationPath+" ("+e.Message+")");
                        }
                        decompressedStream.Close();
                    }
                }

                this.fileStream.Close();
                System.IO.File.Delete(GetFilePath(FileAssmeblyRootLocation.cache));//delete the temp file

            }
            else if(this.fileStreamType==FileStreamTypes.HttpPostMimeMultipartFormData) {
                Mime.UnbufferedReader mimeReader=new PacketParser.Mime.UnbufferedReader(this.fileStream);

                List<Mime.MultipartPart> parts=new List<PacketParser.Mime.MultipartPart>();
                foreach(Mime.MultipartPart part in Mime.PartBuilder.GetParts(mimeReader, this.Details)) {
                    parts.Add(part);
                }

                this.parentAssemblerList.PacketHandler.ExtractMultipartFormData(parts, this.fiveTuple, this.transferIsClientToServer, timestamp, this.initialFrameNumber, ApplicationLayerProtocol.Unknown);

                foreach(Mime.MultipartPart part in parts){
                    if(part.Attributes["filename"]!=null && part.Attributes["filename"].Length>0 && part.Data!=null && part.Data.Length>0) {
                        //we have a file!
                        string mimeFileLocation=part.Attributes["filename"];
                        if(mimeFileLocation.Contains("/"))
                            mimeFileLocation=mimeFileLocation.Substring(0, mimeFileLocation.LastIndexOf('/'));
                        if(mimeFileLocation.Contains("\\"))
                            mimeFileLocation=mimeFileLocation.Substring(0, mimeFileLocation.LastIndexOf('\\'));
                        string mimeFileName=part.Attributes["filename"];
                        if(mimeFileName.Contains("/") && mimeFileName.Length>mimeFileName.LastIndexOf('/')+1)
                            mimeFileName=mimeFileName.Substring(mimeFileName.LastIndexOf('/')+1);
                        if(mimeFileName.Contains("\\") && mimeFileName.Length>mimeFileName.LastIndexOf('\\')+1)
                            mimeFileName=mimeFileName.Substring(mimeFileName.LastIndexOf('\\')+1);


                        using(FileStreamAssembler partAssembler=new FileStreamAssembler(this.parentAssemblerList, this.fiveTuple, this.transferIsClientToServer, FileStreamTypes.HttpPostMimeFileData, mimeFileName, mimeFileLocation, part.Attributes["filename"], this.initialFrameNumber, this.timestamp)) {
                            this.parentAssemblerList.Add(partAssembler);
                            partAssembler.FileContentLength=part.Data.Length;
                            partAssembler.FileSegmentRemainingBytes=part.Data.Length;
                            if(partAssembler.TryActivate()) {
                                partAssembler.AddData(part.Data, 0);
                            }
                        }
                    }
                }
                this.fileStream.Close();
                System.IO.File.Delete(GetFilePath(FileAssmeblyRootLocation.cache));
            }
            else {//files which are already completed can simply be moved to their final destination
                if(this.fileStream != null)
                    this.fileStream.Close();
                try {
                    string tmpPath = GetFilePath(FileAssmeblyRootLocation.cache);
                    if(System.IO.File.Exists(tmpPath))
                        System.IO.File.Move(tmpPath, destinationPath);
                }
                catch(Exception e) {
                    this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error moving file \""+GetFilePath(FileAssmeblyRootLocation.cache) +"\" to \""+destinationPath+"\". "+e.Message);
                }
            }
            if(System.IO.File.Exists(destinationPath)) {
                /*
                try {
                    System.IO.File.SetLastWriteTime(destinationPath, this.timestamp);
                }
                catch (Exception e) {
                    this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error timestomping reconstructed file: " + e.Message);
                }
                */

                try {
                    ReconstructedFile completedFile=new ReconstructedFile(destinationPath, this.fiveTuple, this.transferIsClientToServer, fileStreamType, details, this.initialFrameNumber, this.timestamp, this.serverHostname);

                    //only report on partial files (from range requests) if settings say so
                    if (parentAssemblerList.PacketHandler.ExtractPartialDownloads || this.contentRange == null || completedFile.FileSize == contentRange.Total) {
                        parentAssemblerList.PacketHandler.AddReconstructedFile(completedFile);
                        if (this.FileReconstructed != null)
                            this.FileReconstructed(this.extendedFileId, completedFile);
                    }

                    //reassemble file from HTTP range replies like "HTTP/1.1 206 Partial Content"
                    if (this.contentRange != null) {

                        string fileKey;
                        if(this.details == null || this.details.Length == 0)
                            fileKey = this.SourceHost.IPAddress.ToString() + "|" + contentRange.Total.ToString();
                        else
                            fileKey = this.details + "|" + contentRange.Total.ToString();
                        PartialFileAssembler partialFileAssembler;
                        if (this.parentAssemblerList.PartialFileAssemblerList.ContainsKey(fileKey))
                            partialFileAssembler = this.parentAssemblerList.PartialFileAssemblerList[fileKey];
                        else {
                            partialFileAssembler = new PartialFileAssembler(fileAssmeblyRootLocation, this.fiveTuple, this.transferIsClientToServer, this.fileStreamType, this.fileLocation, this.filename, this.parentAssemblerList, this.details, contentRange.Total, this.initialFrameNumber, this.serverHostname);
                            this.parentAssemblerList.PartialFileAssemblerList.Add(fileKey, partialFileAssembler);
                        }

                        partialFileAssembler.AddFile(completedFile, this.contentRange);

                        if (partialFileAssembler.IsComplete()) {
                            ReconstructedFile reconstructedFile = partialFileAssembler.Reassemble();
                            this.parentAssemblerList.PartialFileAssemblerList.Remove(fileKey);
                            if (reconstructedFile != null) {
                                /*
                                //this file also needs to be timestomped
                                try {
                                    System.IO.File.SetLastWriteTime(reconstructedFile.FilePath, reconstructedFile.Timestamp);
                                }
                                catch (Exception e) {
                                    this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error timestomping reconstructed file: " + e.Message);
                                }
                                */
                                parentAssemblerList.PacketHandler.AddReconstructedFile(reconstructedFile);
                                if (this.FileReconstructed != null)
                                    this.FileReconstructed(this.extendedFileId, reconstructedFile);
                            }
                        }
                    }

                }
                catch(Exception e) {
                    this.parentAssemblerList.PacketHandler.OnAnomalyDetected("Error creating reconstructed file: "+e.Message);
                }
            }
        
        }

        
        //this one might generate exceptions thatt needs to be catched further up in the hierarchy!!!
        internal void WriteStreamToFile(System.IO.Stream stream, string destinationPath) {

            using(System.IO.FileStream outputFile=new System.IO.FileStream(destinationPath, System.IO.FileMode.Create)) {
                byte[] buffer=new byte[1024];
                while(true) {//I don't like while(true) loops, but they used it at ms-help://MS.VSCC.v80/MS.MSDN.v80/MS.NETDEVFX.v20.en/cpref8/html/T_System_IO_Compression_CompressionMode.htm
                    int bytesRead=stream.Read(buffer, 0, buffer.Length);
                    if(bytesRead==0)
                        break;
                    outputFile.Write(buffer, 0, bytesRead);
                }
                outputFile.Close();
            }
        }

        /// <summary>
        /// Removes the data in the buffer, closes the file stream and deletes the temporary file.
        /// But the assembler is not removed from the parentAssemblerList!
        /// </summary>
        internal void Clear() {
            this.tcpPacketBufferWindow.Clear();
            if(this.fileStream!=null) {
                this.fileStream.Close();
                if(System.IO.File.Exists(this.fileStream.Name))
                    System.IO.File.Delete(this.fileStream.Name);

                //System.IO.File.Delete(GetFilePath(true));
                this.fileStream=null;
            }
        }

        internal class DeChunkedDataStream : System.IO.Stream, IDisposable {
            //private int position;//should be long
            private System.IO.Stream chunkedStream;
            private int currentChunkSize;
            private int readBytesInCurrentChunk;

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
                get { throw new Exception("The method or operation is not implemented."); }
            }

            public override long Position {
                get {
                    throw new Exception("The method or operation is not implemented.");
                }
                set {
                    throw new Exception("The method or operation is not implemented.");
                }
            }

            public DeChunkedDataStream(System.IO.Stream chunkedStream) {
                this.chunkedStream=chunkedStream;
                //this.position=0;//should be long
                this.currentChunkSize=0;
                this.readBytesInCurrentChunk=0;
            }

            public override int Read(byte[] buffer, int offset, int count) {
                int bytesRead=0;
                if(this.readBytesInCurrentChunk>=this.currentChunkSize){//I need to read a new chunk
                    StringBuilder chunkSizeString=new StringBuilder();//chunk-size as hex-string
                    while(true){
                        int ib=chunkedStream.ReadByte();
                        if(ib<0)//end of stream
                            return 0;

                        byte b=(byte)ib;
                        if(b!=0x0d) {
                            char c=(char)b;
                            string hexCharacters="0123456789abcdefABCDEF";

                            if(hexCharacters.Contains(""+c))
                                chunkSizeString.Append((char)b);
                        }
                        else {
                            chunkedStream.ReadByte();//this should be the 0x0a that follows the 0x0d
                            if(chunkSizeString.Length>0)//there are sometimes CRLF before the chunk-size value
                                break;
                        }
                    }
                    if(chunkSizeString.ToString().Length==0)
                        this.currentChunkSize=0;//I'm not sure if this line should really be needed...
                    else
                        this.currentChunkSize=Convert.ToInt32(chunkSizeString.ToString(), 16);
                    this.readBytesInCurrentChunk=0;

                    if(this.currentChunkSize==0)//end of chunk-stream
                        return 0;
                }

                bytesRead=this.chunkedStream.Read(buffer, offset, Math.Min(count, this.currentChunkSize-this.readBytesInCurrentChunk));
                this.readBytesInCurrentChunk+=bytesRead;

                //see if I have to start reading the next chunk as well....
                if(bytesRead<count && this.readBytesInCurrentChunk==this.currentChunkSize){
                    //we are at the end of the chunk
                    return bytesRead+this.Read(buffer, offset+bytesRead, count-bytesRead);//nice recursive stuff
                }
                else
                    return bytesRead;
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

            #region IDisposable Members

            public new void Dispose() {
                //throw new Exception("The method or operation is not implemented.");
                if(this.chunkedStream!=null) {
                    this.chunkedStream.Close();
                    this.chunkedStream=null;
                }
                
                base.Dispose();
            }

            #endregion
        }

        #region IDisposable Members

        public void Dispose() {
            //throw new Exception("The method or operation is not implemented.");
            if(this.fileStream!=null) {
                this.fileStream.Close();
                this.fileStream=null;
            }
        }

        #endregion
    }
}
