//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.FileTransfer {
    public class ReconstructedFile {

        private string path, details;
        //private NetworkHost sourceHost, destinationHost;
        //private ushort sourcePort, destinationPort;
        //private bool tcpTransfer;
        private FiveTuple fiveTuple;
        private bool transferIsClientToServer;

        private FileStreamTypes fileStreamType;
        private long fileSize;

        private string filename;

        private long initialFrameNumber;
        private DateTime timestamp;
        private string serverHostname;//host header in HTTP

        private string md5Sum=null;//uses lazy initialization

        public string FilePath { get { return this.path; } }
        public FiveTuple FiveTuple { get { return this.fiveTuple; } }
        public bool TransferIsClientToServer { get { return this.transferIsClientToServer; } }
        public NetworkHost SourceHost { get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ClientHost;
                else
                    return this.fiveTuple.ServerHost;
            }
        }
        internal ushort SourcePort {
            get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ClientPort;
                else
                    return this.fiveTuple.ServerPort;
            }
        }
        internal ushort DestinationPort {
            get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ServerPort;
                else
                    return this.fiveTuple.ClientPort;
            }
        }
        public string SourcePortString { get { return this.GetTransportProtocol().ToString()+" "+this.SourcePort; } }
        public NetworkHost DestinationHost {
            get {
                if (this.transferIsClientToServer)
                    return this.fiveTuple.ServerHost;
                else
                    return this.fiveTuple.ClientHost;
            }
        }
        public string DestinationPortString { get { return this.GetTransportProtocol().ToString() + " "+this.DestinationPort; } }
        public string Filename { get { return this.filename; } }
        public long FileSize { get { return this.fileSize; } }
        public string FileSizeString {
            get {
                //return string.Format(new 
                System.Globalization.NumberFormatInfo nfi=new System.Globalization.NumberFormatInfo();
                nfi.NumberDecimalDigits=0;
                nfi.NumberGroupSizes=new int[] {3};
                nfi.NumberGroupSeparator=" ";
                //nfi.
                return this.fileSize.ToString("N", nfi)+" B";
            } }
        public string Details { get { return this.details; } }
        public FileStreamTypes FileStreamType { get { return this.fileStreamType; } }
        public long InitialFrameNumber { get { return this.initialFrameNumber; } }
        public DateTime Timestamp { get { return this.timestamp; } }
        public string ServerHostname { get { return this.serverHostname; } }

        public string MD5Sum {
            get {
                //this parameter uses lazy initialization
                if(this.md5Sum==null)
                    this.md5Sum=PcapFileHandler.Md5SingletonHelper.Instance.GetMd5Sum(this.path);
                return this.md5Sum;
            }
        }

        private string GetFileEnding() {
            if(!filename.Contains("."))
                return "";
            if(filename.EndsWith("."))
                return "";
            return this.filename.Substring(filename.LastIndexOf('.')+1).ToLower();
        }

        public bool IsImage() {
            string fileEnding=GetFileEnding();
            if(fileEnding.Length==0)
                return false;
            if(fileEnding=="jpg" || fileEnding=="jpeg" || fileEnding=="gif" || fileEnding=="png" || fileEnding=="bmp" || fileEnding=="tif" || fileEnding=="tiff")
                return true;
            else
                return false;
        }

        public bool IsIcon() {
            string fileEnding=GetFileEnding();
            if(fileEnding.Length==0)
                return false;
            if (fileEnding == "ico" || fileEnding == "icon" || fileEnding == "x-icon")
                return true;
            else if (this.filename.Contains("favicon")) {
                byte[] b = this.GetHeaderBytes(12);
                if (b[0] == 0 && b[1] == 0 && b[2] == 1 && b[3] == 0 && b[4] == 1 && b[5] == 0 && b[9] == 0 && b[11] == 0)
                    return true;
            }
            return false;
        }

        public bool IsMultipartFormData() {
            string fileEnding=GetFileEnding();
            if(fileEnding.Length==0)
                return false;
            if(fileEnding=="mime")
                return true;
            else
                return false;
        }



        internal ReconstructedFile(string path, FiveTuple fiveTuple, bool transferIsClientToServer, FileStreamTypes fileStreamType, string details, long initialFrameNumber, DateTime timestamp, string serverHostname) {
            this.path=path;
            try {
                if(path.Contains("\\"))
                    this.filename=path.Substring(path.LastIndexOf('\\')+1);
                else if(path.Contains("/"))
                    this.filename=path.Substring(path.LastIndexOf('/')+1);
                else
                    this.filename=path;

            }
            catch(Exception) {
                this.filename="";
            }
            this.fiveTuple = fiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;
            /*
            this.sourceHost=sourceHost;
            this.destinationHost=destinationHost;
            this.sourcePort=sourcePort;
            this.destinationPort=destinationPort;
            this.tcpTransfer=tcpTransfer;
            */
            this.fileStreamType=fileStreamType;
            this.details=details;

            System.IO.FileInfo fi=new System.IO.FileInfo(path);
            this.fileSize=fi.Length;
            this.initialFrameNumber=initialFrameNumber;
            this.timestamp=timestamp;
            this.serverHostname = serverHostname;

            //PacketParser.Utils.Logger.Log("Reconstructed file: " + fi.Name, System.Diagnostics.EventLogEntryType.Information);

        }

        private FiveTuple.TransportProtocol GetTransportProtocol() {
            return this.fiveTuple.Transport;
        }

        public override string ToString() {
            string sourceInfo;
            string destinationInfo;
            sourceInfo=this.SourceHost.ToString()+" " + this.fiveTuple.Transport.ToString() + " " + this.SourcePort;
            destinationInfo=this.DestinationHost.ToString()+ " " + this.fiveTuple.Transport.ToString() + " " + this.DestinationPort;

            return filename+"\t"+sourceInfo+"\t"+destinationInfo;

        }

        public byte[] GetHeaderBytes(int nBytes) {

            using (System.IO.FileStream fileStream = new System.IO.FileStream(this.path, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.ReadWrite, nBytes, System.IO.FileOptions.SequentialScan)) {

                byte[] bytes = new byte[nBytes];
                int bytesRead = fileStream.Read(bytes, 0, nBytes);
                fileStream.Close();
                if (bytesRead >= nBytes)
                    return bytes;
                else if (bytesRead < 0)
                    return null;
                else { //0 <= bytesRead < nBytes)
                    byte[] b = new byte[bytesRead];
                    Array.Copy(bytes, b, bytesRead);
                    return b;
                }
            }
        }

    }
}
