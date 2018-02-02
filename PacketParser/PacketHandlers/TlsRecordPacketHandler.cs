//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.PacketHandlers {
    class TlsRecordPacketHandler : AbstractPacketHandler, ITcpSessionPacketHandler {

        public ApplicationLayerProtocol HandledProtocol {
            get { return ApplicationLayerProtocol.Ssl; }
        }

        public TlsRecordPacketHandler(PacketHandler mainPacketHandler)
            : base(mainPacketHandler) {
            //empty constructor
        }

        #region ITcpSessionPacketHandler Members

        //public int ExtractData(NetworkTcpSession tcpSession, NetworkHost sourceHost, NetworkHost destinationHost, IEnumerable<Packets.AbstractPacket> packetList) {
        public int ExtractData(NetworkTcpSession tcpSession, bool transferIsClientToServer, IEnumerable<PacketParser.Packets.AbstractPacket> packetList) {
            
            bool successfulExtraction=false;


            Packets.TcpPacket tcpPacket=null;
            foreach(Packets.AbstractPacket p in packetList)
                if(p.GetType()==typeof(Packets.TcpPacket))
                    tcpPacket=(Packets.TcpPacket)p;
            int parsedBytes = 0;
            if(tcpPacket!=null) {
                
                //there might be several TlsRecordPackets in an SSL packet
                foreach(Packets.AbstractPacket p in packetList) {
                    if(p.GetType()==typeof(Packets.TlsRecordPacket)) {
                        Packets.TlsRecordPacket tlsRecordPacket=(Packets.TlsRecordPacket)p;
                        if(tlsRecordPacket.TlsRecordIsComplete) {
                            ExtractTlsRecordData(tlsRecordPacket, tcpPacket, tcpSession.Flow.FiveTuple, transferIsClientToServer, base.MainPacketHandler);
                            successfulExtraction=true;
                            parsedBytes += tlsRecordPacket.Length+5;
                        }
                        else if(tlsRecordPacket.Length>4000) {//it should have been complete, so just skip it... there is no point in reassembling it any more
                            successfulExtraction=true;
                            parsedBytes = tcpPacket.PayloadDataLength;
                        }
                    }
                }
            }

            if(successfulExtraction) {
                return parsedBytes;
                //return tcpPacket.PayloadDataLength;
            }
            else
                return 0;
        }

        public void Reset() {
            //noting here since this object holds no state
        }

        #endregion

        private void ExtractTlsRecordData(Packets.TlsRecordPacket tlsRecordPacket, Packets.TcpPacket tcpPacket, FiveTuple fiveTuple, bool transferIsClientToServer, PacketHandler mainPacketHandler) {
            NetworkHost sourceHost, destinationHost;
            if (transferIsClientToServer) {
                sourceHost = fiveTuple.ClientHost;
                destinationHost = fiveTuple.ServerHost;
            }
            else {
                sourceHost = fiveTuple.ServerHost;
                destinationHost = fiveTuple.ClientHost;
            }

            foreach (Packets.AbstractPacket p in tlsRecordPacket.GetSubPackets(false)) {
                if(p.GetType()==typeof(Packets.TlsRecordPacket.HandshakePacket)) {
                    Packets.TlsRecordPacket.HandshakePacket handshake=(Packets.TlsRecordPacket.HandshakePacket)p;
                    if(handshake.MessageType == Packets.TlsRecordPacket.HandshakePacket.MessageTypes.ClientHello) {
                        if(handshake.ServerHostName != null) {
                            destinationHost.AddHostName(handshake.ServerHostName);
                            System.Collections.Specialized.NameValueCollection param = new System.Collections.Specialized.NameValueCollection();
                            param.Add("TLS Server Name", handshake.ServerHostName);
                            base.MainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(handshake.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, param, handshake.ParentFrame.Timestamp, "TLS Client Hello"));
                        }
                    }
                    else if(handshake.MessageType==Packets.TlsRecordPacket.HandshakePacket.MessageTypes.Certificate)
                        for(int i=0; i<handshake.CertificateList.Count; i++) {
                            byte[] certificate=handshake.CertificateList[i];
                            string x509CertSubject;
                            System.Security.Cryptography.X509Certificates.X509Certificate x509Cert=null;
                            try {
                                x509Cert=new System.Security.Cryptography.X509Certificates.X509Certificate(certificate);
                                x509CertSubject=x509Cert.Subject;
                            }
                            catch {
                                x509CertSubject="Unknown_x509_Certificate_Subject";
                                x509Cert=null;
                            }
                            if (x509CertSubject.Contains("CN="))
                                x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf("CN=") + 3);
                            else if (x509CertSubject.Contains("="))
                                x509CertSubject = x509CertSubject.Substring(x509CertSubject.IndexOf('=') + 1);
                            if (x509CertSubject.Length>28)
                                x509CertSubject=x509CertSubject.Substring(0, 28);
                            if(x509CertSubject.Contains(","))
                                x509CertSubject=x509CertSubject.Substring(0, x509CertSubject.IndexOf(','));

                            x509CertSubject.Trim(new char[] {'.', ' '});
                            /*
                            while (x509CertSubject.EndsWith(".") || x509CertSubject.EndsWith(" "))
                                x509CertSubject=x509CertSubject.Substring(0, x509CertSubject.Length-1);
                                */
                            string filename=x509CertSubject+".cer";
                            string fileLocation="/";
                            string details;
                            if(x509Cert!=null)
                                details="TLS Certificate: "+x509Cert.Subject;
                            else
                                details="TLS Certificate: Unknown x509 Certificate";


                            FileTransfer.FileStreamAssembler assembler=new FileTransfer.FileStreamAssembler(mainPacketHandler.FileStreamAssemblerList, fiveTuple, transferIsClientToServer, FileTransfer.FileStreamTypes.TlsCertificate, filename, fileLocation, certificate.Length, certificate.Length, details, null, tlsRecordPacket.ParentFrame.FrameNumber, tlsRecordPacket.ParentFrame.Timestamp, FileTransfer.FileStreamAssembler.FileAssmeblyRootLocation.source);
                            mainPacketHandler.FileStreamAssemblerList.Add(assembler);
                            if(i == 0 && x509CertSubject.Contains(".") && !x509CertSubject.Contains("*") && !x509CertSubject.Contains(" "))
                                sourceHost.AddHostName(x509CertSubject);
                            System.Collections.Specialized.NameValueCollection parameters = new System.Collections.Specialized.NameValueCollection();
                            //parameters.Add("Certificate Subject", x509Cert.Subject);
                            const string CERTIFICATE_SUBJECT = "Certificate Subject";
                            this.addParameters(parameters, x509Cert.Subject, CERTIFICATE_SUBJECT);
                            if(i==0) {
                                //check for CN parameter
                                if(parameters[CERTIFICATE_SUBJECT + " CN"] != null) {
                                    foreach (string cn in parameters.GetValues(CERTIFICATE_SUBJECT + " CN")) {
                                        sourceHost.AddNumberedExtraDetail("X.509 Certificate Subject CN", cn);
                                        if (cn.Contains(".") && !cn.Contains(" ")) {
                                            if (cn.Contains("*")) {
                                                if (cn.StartsWith("*."))
                                                    sourceHost.AddDomainName(cn.Substring(2));
                                            }
                                            else
                                                sourceHost.AddHostName(cn);
                                        }
                                    }
                                }
                            }

                            this.addParameters(parameters, x509Cert.Issuer, "Certificate Issuer");

                            

                            //parameters.Add("Certificate Issuer", x509Cert.Issuer);
                            parameters.Add("Certificate Hash", x509Cert.GetCertHashString());
                            parameters.Add("Certificate valid from", x509Cert.GetEffectiveDateString());
                            parameters.Add("Certificate valid to", x509Cert.GetExpirationDateString());
                            parameters.Add("Certificate Serial", x509Cert.GetSerialNumberString());
                            try {
                                System.Security.Cryptography.X509Certificates.X509Certificate2 cert2 = new System.Security.Cryptography.X509Certificates.X509Certificate2(certificate);
                                foreach (var ext in cert2.Extensions) {
                                    string fn = ext.Oid.FriendlyName;
                                    string oid = ext.Oid.Value;
                                    string val = ext.Format(true);
                                    System.IO.StringReader sr = new System.IO.StringReader(val);
                                    string line = sr.ReadLine();
                                    while (line != null) {
                                        parameters.Add(oid + " " + fn, line);
                                        if (i == 0 && oid == "2.5.29.17") {
                                            sourceHost.AddNumberedExtraDetail("X.509 Certificate " + fn, line);
                                        }
                                        line = sr.ReadLine();
                                    }
                                }

                                if (cert2.Verify())
                                    parameters.Add("Certificate valid", "TRUE");
                                else
                                    parameters.Add("Certificate valid", "FALSE");

                            }
                            catch (Exception) { }


                            mainPacketHandler.OnParametersDetected(new Events.ParametersEventArgs(tlsRecordPacket.ParentFrame.FrameNumber, fiveTuple, transferIsClientToServer, parameters, tlsRecordPacket.ParentFrame.Timestamp, "X.509 Certificate"));

                            if (assembler.TryActivate())
                                assembler.AddData(certificate, tcpPacket.SequenceNumber);//this one should trigger FinnishAssembling()
                        }
                }
            }

        }

        private void addParameters(System.Collections.Specialized.NameValueCollection parameters, string x509Subject, string parameterName) {
            foreach(string part in x509Subject.Split(new char[] { ',' }))
                if(part.Contains("=")) {
                    parameters.Add(parameterName + " " + part.Substring(0, part.IndexOf('=')).Trim(), part.Substring(part.IndexOf('=') + 1).Trim());
                }
        }
    }
}
