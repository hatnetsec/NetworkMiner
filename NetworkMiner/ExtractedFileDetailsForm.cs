using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

using System.Reflection;

namespace NetworkMiner {

    public partial class ExtractedFileDetailsForm : Form {

        private FileDetails fileDetails;


        public int PropertyGridLabelWidth
        {
            get
            {
                FieldInfo fi = this.fileDetailsPropertyGrid.GetType().GetField("gridView", BindingFlags.Instance | BindingFlags.NonPublic);
                if (fi != null) {
                    Control view = fi.GetValue(fileDetailsPropertyGrid) as Control;
                    if (view != null) {
                        //protected int InternalLabelWidth
                        PropertyInfo propInfo = view.GetType().GetProperty("InternalLabelWidth", BindingFlags.NonPublic | BindingFlags.Instance);
                        return (int)propInfo.GetValue(view, new object[] { });
                    }
                }
                return 0;
            }
            set
            {
                FieldInfo fi = this.fileDetailsPropertyGrid.GetType().GetField("gridView", BindingFlags.Instance | BindingFlags.NonPublic);
                if (fi != null) {
                    Control view = fi.GetValue(fileDetailsPropertyGrid) as Control;
                    if (view != null) {
                        MethodInfo mi = view.GetType().GetMethod("MoveSplitterTo", BindingFlags.Instance | BindingFlags.NonPublic);
                        if (mi != null)
                            mi.Invoke(view, new object[] { value });
                    }
                }
            }
        }


        public ExtractedFileDetailsForm(string filePath) {
            InitializeComponent();
            this.fileDetails = new FileDetails(filePath);
            this.fileDetailsPropertyGrid.SelectedObject = this.fileDetails;
            this.Text = this.fileDetails.Name;
        }

        private void FileDetailsForm_VisibleChanged(object sender, EventArgs e) {

            if (this.Visible) {
                this.BeginInvoke((MethodInvoker)delegate () { this.PropertyGridLabelWidth = 168; });
            }

        }

        [Obfuscation(Feature = "Apply to member * when property and public: renaming", Exclude = true)]
        internal class FileDetails {
            private string path;
            private System.IO.FileInfo fileInfo;
            private string md5, sha1, sha256;


            public string Name { get { return this.fileInfo.Name; } }
            public string MD5 { get { return this.md5; } }
            public string SHA1 { get { return this.sha1; } }
            public string SHA256 { get { return this.sha256; } }
            public string Path { get { return this.path; } }
            public long Size { get { return this.fileInfo.Length; } }
            public DateTime LastWriteTime { get { return this.fileInfo.LastWriteTime; } }


            internal FileDetails(string path) {
                this.path = path;
                this.fileInfo = new System.IO.FileInfo(this.path);
                this.md5 = PcapFileHandler.Md5SingletonHelper.Instance.GetMd5Sum(this.path);
                this.sha1 = PcapFileHandler.Md5SingletonHelper.Instance.GetSha1Sum(this.path);
                this.sha256 = PcapFileHandler.Md5SingletonHelper.Instance.GetSha256Sum(this.path);
            }
        }
    }



        
    
}
