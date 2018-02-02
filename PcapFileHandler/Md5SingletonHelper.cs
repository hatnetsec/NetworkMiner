using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography;

namespace PcapFileHandler {
    public class Md5SingletonHelper {
        private static Md5SingletonHelper instance=null;

        public static Md5SingletonHelper Instance {
            get {
                if(instance==null)
                    instance=new Md5SingletonHelper();
                return instance;
            }
        }

        private MD5 md5;
        private SHA1 sha1;
        private SHA256 sha256;

        private Md5SingletonHelper() {
            this.md5=MD5.Create();
            this.sha1 = SHA1.Create();
            this.sha256 = SHA256.Create();
        }

        public string GetMd5Sum(string file){
            
            byte[] md5hash;
            using(System.IO.FileStream fileStream=new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 262144, System.IO.FileOptions.SequentialScan)) {
                md5hash=md5.ComputeHash(fileStream);
            }
            StringBuilder sb=new StringBuilder();
            foreach(byte b in md5hash) {
                sb.Append(b.ToString("X2").ToLower());
            }
            
            return sb.ToString();
        }

        public string GetSha1Sum(string file) {

            byte[] sha1hash;
            using (System.IO.FileStream fileStream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 262144, System.IO.FileOptions.SequentialScan)) {
                sha1hash = sha1.ComputeHash(fileStream);
            }
            StringBuilder sb = new StringBuilder();
            foreach (byte b in sha1hash) {
                sb.Append(b.ToString("X2").ToLower());
            }

            return sb.ToString();
        }

        public string GetSha256Sum(string file) {

            byte[] sha256hash;
            using (System.IO.FileStream fileStream = new System.IO.FileStream(file, System.IO.FileMode.Open, System.IO.FileAccess.Read, System.IO.FileShare.Read, 262144, System.IO.FileOptions.SequentialScan)) {
                sha256hash = sha256.ComputeHash(fileStream);
            }
            StringBuilder sb = new StringBuilder();
            foreach (byte b in sha256hash) {
                sb.Append(b.ToString("X2").ToLower());
            }

            return sb.ToString();
        }
    }
}
