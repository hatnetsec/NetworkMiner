using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Mime {
    public class Email {

        public static string GetFileId(System.Collections.Specialized.NameValueCollection rootAttributes) {

            if (rootAttributes["Message-ID"] != null && rootAttributes["Message-ID"].Length > 0)
                return rootAttributes["Message-ID"];
            StringBuilder sb = new StringBuilder();
            if (rootAttributes["Subject"] != null)
                sb.Append(rootAttributes["Subject"]);
            if (rootAttributes["Date"] != null)
                sb.Append(rootAttributes["Date"]);
            return sb.ToString();
        }

        

        public string From { get { return this.from; } }
        public string To { get { return this.to; } }
        public string Subject { get { return this.subject; } }
        public string MessageID { get { return this.MessageID; } }
        public string DateString { get { return this.date; } }
        public IEnumerable<FileTransfer.ReconstructedFile> Attachments { get { return this.attachments; } }

        internal readonly PacketHandler MainPacketHandler;

        private string from;
        private string to;
        private string subject;
        private string messageId;
        private string date;//Date: Fri, 1 Aug 2003 14:17:51 -0700
        private FileTransfer.FileStreamTypes fileTransferProtocol;
        private ApplicationLayerProtocol protocol;
        private List<FileTransfer.ReconstructedFile> attachments;
        //private bool reassembleFileAtSourceHost;
        private FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation;
        private FiveTuple fiveTuple;
        private bool transferIsClientToServer;

        public Email(System.IO.MemoryStream emailMimeStream, PacketHandler mainPacketHandler, Packets.TcpPacket tcpPacket, bool transferIsClientToServer, NetworkTcpSession tcpSession, ApplicationLayerProtocol protocol, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation fileAssmeblyRootLocation = FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.destination) {
            Mime.UnbufferedReader ur = new PacketParser.Mime.UnbufferedReader(emailMimeStream);
            this.MainPacketHandler = mainPacketHandler;
            this.protocol = protocol;
            if (this.protocol == ApplicationLayerProtocol.Smtp)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.SMTP;
            else if (this.protocol == ApplicationLayerProtocol.Pop3)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.POP3;
            else if (this.protocol == ApplicationLayerProtocol.Imap)
                this.fileTransferProtocol = FileTransfer.FileStreamTypes.IMAP;
            //this.reassembleFileAtSourceHost = reassembleFileAtSourceHost;
            this.fileAssmeblyRootLocation = fileAssmeblyRootLocation;

            this.fiveTuple = tcpSession.Flow.FiveTuple;
            this.transferIsClientToServer = transferIsClientToServer;

            this.attachments = new List<FileTransfer.ReconstructedFile>();
            this.from = null;
            this.to = null;
            this.subject = null;
            this.messageId = null;
            this.date = null;//Date: Fri, 1 Aug 2003 14:17:51 -0700
            Encoding customEncoding = null;
            System.Collections.Specialized.NameValueCollection rootAttributes = null;
            bool messageSentToPacketHandler = false;
            foreach (Mime.MultipartPart multipart in Mime.PartBuilder.GetParts(ur)) {//I might need to add "ref customEncoding" as a parameter here
                if (rootAttributes == null) {
                    from = multipart.Attributes["From"];
                    to = multipart.Attributes["To"];
                    subject = multipart.Attributes["Subject"];
                    messageId = multipart.Attributes["Message-ID"];
                    date = multipart.Attributes["Date"];
                    rootAttributes = multipart.Attributes;
                }
                if (multipart.Attributes["charset"] != null) {
                    try {
                        customEncoding = Encoding.GetEncoding(multipart.Attributes["charset"]);
                    }
                    catch { }
                }
                this.parseMultipart(multipart, rootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, from, to, subject, messageId);
            }

            //create an .eml file with the whole DATA portion
            string emlFilename = null;
            if (subject != null && subject.Length > 3) {
                emlFilename = Utils.StringManglerUtil.ConvertToFilename(subject, 10);
                /*
                try {
                    System.IO.FileInfo fi = new System.IO.FileInfo(subject.Substring(0, 10));
                    emlFilename = subject.Substring(0, 10);
                }
                catch {
                    emlFilename = Utils.StringManglerUtil.ConvertToFilename(subject, 10);
                }
                */
            }
            if (emlFilename == null || emlFilename.Length == 0) {
                if (messageId != null && messageId.Length > 3) {
                    emlFilename = Utils.StringManglerUtil.ConvertToFilename(messageId, 10);
                }
                else
                    emlFilename = "message_" + tcpSession.GetHashCode().ToString("X8");
            }


            emlFilename = emlFilename + ".eml";
            /*
            string extendedFileId = tcpSession.GetHashCode().ToString();
            if (messageId != null && messageId.Length > 0)
                extendedFileId = messageId;
                */
            if (rootAttributes != null) {
                string extendedFileId = GetFileId(rootAttributes);
                using (FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, this.fiveTuple, this.transferIsClientToServer, this.fileTransferProtocol, emlFilename, "/", emailMimeStream.Length, emailMimeStream.Length, this.protocol.ToString() + " transcript From: " + from + " To: " + to + " Subject: " + subject, extendedFileId, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.fileAssmeblyRootLocation)) {
                    if (assembler.TryActivate()) {
                        assembler.FileReconstructed += MainPacketHandler.OnMessageAttachmentDetected;
                        assembler.FileReconstructed += Assembler_FileReconstructed;
                        assembler.AddData(emailMimeStream.ToArray(), tcpPacket.SequenceNumber);
                        //assembler.FinishAssembling();

                    }
                    else {
                        assembler.Clear();
                        assembler.FinishAssembling();
                    }
                }
            }
        }

        private void Assembler_FileReconstructed(string extendedFileId, FileTransfer.ReconstructedFile file) {
            this.attachments.Add(file);
        }

        private void parseMultipart(Mime.MultipartPart multipart, System.Collections.Specialized.NameValueCollection rootAttributes, Packets.TcpPacket tcpPacket, /*NetworkHost sourceHost, NetworkHost destinationHost, */ref bool messageSentToPacketHandler, Encoding customEncoding, string from = null, string to = null, string subject = null, string messageId = null) {
            if (multipart.Attributes.Count > 0) {
                this.MainPacketHandler.OnParametersDetected(new PacketParser.Events.ParametersEventArgs(tcpPacket.ParentFrame.FrameNumber, this.fiveTuple, this.transferIsClientToServer, multipart.Attributes, tcpPacket.ParentFrame.Timestamp, this.protocol + " packet"));
            }
            string contentType = multipart.Attributes["Content-Type"];
            string charset = multipart.Attributes["charset"];
            if (charset != null && charset.Length > 0) {
                try {
                    customEncoding = System.Text.Encoding.GetEncoding(charset);
                }
                catch { };
            }
            bool attachment = false;
            string contentDisposition = multipart.Attributes["Content-Disposition"];
            if (contentDisposition != null && contentDisposition.Contains("attachment"))
                attachment = true;
            if (contentType != null && (
                contentType.Equals("multipart/mixed", StringComparison.InvariantCultureIgnoreCase) ||
                contentType.Equals("multipart/alternative", StringComparison.InvariantCultureIgnoreCase) ||
                contentType.Equals("multipart/related", StringComparison.InvariantCultureIgnoreCase)
                )) {
                /**
                 * There are a variety of ways to attach images to an email.
                 * Content types are used to identify what is contained by each part of the email.
                 * As well as the various types of image, and text/plain and text/html for the text and HTML parts,
                 * there are various containers: 
                 * multipart/alternative as a container for parts containing the same information in different formats,
                 * multipart/related as a container for parts that are linked in some way, and
                 * multipart/mixed as a general container.
                 **/

                //Mime.MultipartPart mimeMultipart = new Mime.MultipartPart(multipart.Data);
                System.IO.Stream mixedStream = new System.IO.MemoryStream(multipart.Data);
                Mime.UnbufferedReader mixedReader = new PacketParser.Mime.UnbufferedReader(mixedStream);
                string boundary = mixedReader.ReadLine(200, customEncoding);
                if(boundary != null && boundary.Length == 0)//there was an empty line before the boundary, try to read it again
                    boundary = mixedReader.ReadLine(200, customEncoding);
                if (boundary != null && boundary.StartsWith("--")) {
                    boundary = boundary.Substring(2);
                    List<Mime.MultipartPart> innerParts = new List<Mime.MultipartPart>(Mime.PartBuilder.GetParts(mixedReader, boundary, customEncoding));
                    foreach (Mime.MultipartPart innerPart in innerParts) {
                        //a bit of recursion here
                        this.parseMultipart(innerPart, rootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, from, to, subject, messageId);
                    }
                }
            }
            else if (!attachment && contentType == null || !attachment && contentType != null && (contentType.Equals("text/plain", StringComparison.InvariantCultureIgnoreCase) || !messageSentToPacketHandler && contentType.Equals("text/html", StringComparison.InvariantCultureIgnoreCase))) {
                //print the data as text
                //string textData = null;
                byte[] textDataBytes = null;
                if (multipart.Attributes["Content-Transfer-Encoding"] == "quoted-printable") {
                    textDataBytes = Utils.ByteConverter.ReadQuotedPrintable(multipart.Data).ToArray();
                    //textData = Utils.ByteConverter.ReadString();
                }
                else if (multipart.Attributes["Content-Transfer-Encoding"] == "base64") {
                    textDataBytes = System.Convert.FromBase64String(Utils.ByteConverter.ReadString(multipart.Data));
                    //textData = Utils.ByteConverter.ReadString();
                }
                else {
                    textDataBytes = multipart.Data;
                    //textData = Utils.ByteConverter.ReadString();
                }
                string textData = null;
                if (customEncoding == null)
                    textData = Utils.ByteConverter.ReadString(textDataBytes);
                else
                    textData = customEncoding.GetString(textDataBytes);
                if (textData != null) {
                    Dictionary<string, string> aggregatedAttributeDictionary = new Dictionary<string, string>();
                    System.Collections.Specialized.NameValueCollection aggregatedAttributes = new System.Collections.Specialized.NameValueCollection();
                    aggregatedAttributes.Add(rootAttributes);
                    foreach (string name in rootAttributes.Keys)
                        aggregatedAttributeDictionary.Add(name, rootAttributes[name]);
                    foreach (string name in multipart.Attributes)
                        if (!aggregatedAttributeDictionary.ContainsKey(name)) {
                            aggregatedAttributeDictionary.Add(name, multipart.Attributes[name]);
                            aggregatedAttributes.Add(name, multipart.Attributes[name]);
                        }
                    if (textData.Length > 0) {
                        if (this.transferIsClientToServer)
                            this.MainPacketHandler.OnMessageDetected(new PacketParser.Events.MessageEventArgs(this.protocol, this.fiveTuple.ClientHost, this.fiveTuple.ServerHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, from, to, subject, textData, customEncoding, aggregatedAttributes));
                        else
                            this.MainPacketHandler.OnMessageDetected(new PacketParser.Events.MessageEventArgs(this.protocol, this.fiveTuple.ServerHost, this.fiveTuple.ClientHost, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, from, to, subject, textData, customEncoding, aggregatedAttributes));
                    }
                    messageSentToPacketHandler = true;
                    if (contentType != null && contentType.Equals("text/html", StringComparison.InvariantCultureIgnoreCase)) {
                        //re-parse the multipart so that it is also extracted to an HTML file
                        this.parseMultipart(multipart, rootAttributes, tcpPacket, ref messageSentToPacketHandler, customEncoding, from, to, subject, messageId);
                    }
                }
            }
            else {
                //store the stuff to disk
                string filename = multipart.Attributes["name"];
                if (filename == null || filename.Length == 0)
                    filename = multipart.Attributes["filename"];
                if (filename == null || filename.Length == 0) {
                    if (subject != null && subject.Length > 3) {
                        filename = Utils.StringManglerUtil.ConvertToFilename(subject, 10);
                    }
                    else if (messageId != null && messageId.Length > 3) {
                        filename = Utils.StringManglerUtil.ConvertToFilename(messageId, 10);
                    }
                    if (filename == null || filename.Length < 3)
                        filename = "email_" + (multipart.GetHashCode() % 1000);

                    string extension = Utils.StringManglerUtil.GetExtension(contentType);
                    if (extension == null || extension.Length < 1)
                        extension = "dat";
                    filename = filename + "." + extension;
                }

                List<byte> fileData = new List<byte>();
                if (multipart.Attributes["Content-Transfer-Encoding"] == "base64") {
                    //decode base64 stuff
                    int index = 0;
                    while (index < multipart.Data.Length) {
                        string base64 = Utils.ByteConverter.ReadLine(multipart.Data, ref index);
                        if (base64 == null && index < multipart.Data.Length) {
                            //read the remaining data
                            base64 = Utils.ByteConverter.ReadString(multipart.Data, index, multipart.Data.Length - index, false, false);
                            index = multipart.Data.Length;
                        }
#if DEBUG
                        if (base64 == null)
                            System.Diagnostics.Debugger.Break();
#endif
                        //if (base64 != null && base64.Length > 0) {
                        try {
                            fileData.AddRange(Convert.FromBase64String(base64));
                        }
                        catch (FormatException e) { }
                    }
                }
                else if (multipart.Attributes["Content-Transfer-Encoding"] == "quoted-printable") {
                    //must be decoded according to http://www.ietf.org/rfc/rfc2045.txt
                    fileData = Utils.ByteConverter.ReadQuotedPrintable(multipart.Data);
                }
                else {
                    //Add the raw data
                    fileData.AddRange(multipart.Data);
                }

                if (fileData != null && fileData.Count > 0) {
                    string fileId = GetFileId(rootAttributes);

                    FileTransfer.FileStreamAssembler assembler = new FileTransfer.FileStreamAssembler(MainPacketHandler.FileStreamAssemblerList, this.fiveTuple, this.transferIsClientToServer, this.fileTransferProtocol, filename, "/", fileData.Count, fileData.Count, "E-mail From: " + from + " To: " + to + " Subject: " + subject, fileId, tcpPacket.ParentFrame.FrameNumber, tcpPacket.ParentFrame.Timestamp, this.fileAssmeblyRootLocation);
                    if (assembler.TryActivate()) {
                        assembler.FileReconstructed += MainPacketHandler.OnMessageAttachmentDetected;
                        assembler.AddData(fileData.ToArray(), tcpPacket.SequenceNumber);
                        //assembler.FinishAssembling();
                    }
                    else {
                        assembler.Clear();
                        assembler.FinishAssembling();
                    }
                }

            }
        }
    }
}
