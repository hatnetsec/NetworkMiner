using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.PcapOverIP {
    internal class ServerCert : System.Security.Cryptography.X509Certificates.X509Certificate2 {

        /**
         * 
         * Password: netresec
         * SSL X509 certificate created like this:
         * openssl genrsa -des3 -out rsaPriv.pem 1024
         * openssl req -new -x509 -key rsaPriv.pem -out cacert.pem -days 4000
         * openssl pkcs12 -export -in cacert.pem -out netresec.p12 -name "Netresec" -inkey rsaPriv.pem
         * base64 netresec.p12 (or open in notepad++ and run plugins/MIME/Base64 Encode)
         **/

        private static ServerCert singletonInstance = null;

        internal static ServerCert Instance {
            get {
                if (singletonInstance == null)
                    singletonInstance = new ServerCert();
                return singletonInstance;
            }
        }

        private ServerCert() : base() {
            string base64RawData = "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";
            byte[] certRawData = System.Convert.FromBase64String(base64RawData);
            base.Import(certRawData, "netresec", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
        }
    }
}
