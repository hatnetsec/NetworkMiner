using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;

namespace NetworkMiner {
    public partial class UpdateCheck : Form {

        public static string CachedLocalVersionCode = null;

        public static void ShowNewVersionFormIfAvailableAsync(Form parentForm, Version localVersion, bool showMessageBoxIfNoUpdate = false) {
            byte[] extra = null;
            if (PacketParser.Utils.SystemHelper.IsRunningOnMono())
                extra = Encoding.ASCII.GetBytes("Mono");
            //public Version(int major, int minor, int build, int revision)
            if(CachedLocalVersionCode == null)
                ShowNewVersionFormIfAvailableAsync(parentForm, localVersion, "1" + localVersion.Major + localVersion.Minor + localVersion.Build, extra);
            else
                ShowNewVersionFormIfAvailableAsync(parentForm, localVersion, CachedLocalVersionCode, extra, showMessageBoxIfNoUpdate);
        }

        public static void ShowNewVersionFormIfAvailableAsync(Form parentForm, Version localVersion, string localVersionCode, byte[] extra = null, bool showMessageBoxIfNoUpdate = false) {
            if (CachedLocalVersionCode == null)
                CachedLocalVersionCode = localVersionCode;

            System.Threading.Tasks.Task.Factory.StartNew(() => {

                try {
                    string requestURL = "https://www.netresec.com/updatecheck.ashx?l=" + System.Web.HttpUtility.UrlEncode(localVersionCode);
                    if (extra != null && extra.Length > 0)
                        requestURL += "&e=" + System.Web.HttpUtility.UrlEncode(Convert.ToBase64String(extra));
                    PacketParser.Utils.Logger.Log("Checking for updates", System.Diagnostics.EventLogEntryType.Information);
                    //System.IO.Stream resultStream = client.GetStreamAsync(requestURL).Result;
                    HttpWebRequest request = WebRequest.Create(requestURL) as HttpWebRequest;
                    
                    string versionString, releasePost, downloadUrl;
                    //using (System.IO.TextReader reader = new System.IO.StreamReader(resultStream)) {
                    using (WebResponse response = request.GetResponse()) {
                        using (System.IO.Stream stream = response.GetResponseStream()) {
                            using (System.IO.TextReader reader = new System.IO.StreamReader(stream)) {

                                versionString = reader.ReadLine();
                                releasePost = reader.ReadLine();
                                downloadUrl = reader.ReadLine();
                            }
                        }
                    }
                    Version latestVersion = Version.Parse(versionString);
                    if (latestVersion > localVersion) {
                        PacketParser.Utils.Logger.Log("Newer version available: " + versionString, System.Diagnostics.EventLogEntryType.Information);
                        parentForm.Invoke(new Action(() => {
                            UpdateCheck form = new UpdateCheck(versionString, releasePost, downloadUrl);
                            form.ShowDialog();
                        }));//end of invoke
                    }
                    else if(showMessageBoxIfNoUpdate) {
                        parentForm.Invoke(new Action(() => {
                            MessageBox.Show("You are running the latest version of NetworkMiner (" + localVersion.ToString() + ")", "No update required");
                        }));
                        PacketParser.Utils.Logger.Log("This is the latest version", System.Diagnostics.EventLogEntryType.Information);
                    }

                }
                catch (Exception e) {
                    //this exception might never be logged, maybe because the thread dies?
                    PacketParser.Utils.Logger.Log(e.Message, System.Diagnostics.EventLogEntryType.Error);
                }
            });//end of task
        }

        public UpdateCheck(string newVersion, string releasePost, string downloadUrl) {
            InitializeComponent();
            this.Text = "Version " + newVersion + " available";
            this.newVersionTextBox.Text = "There is a newer version of NetworkMiner available. Please update to version " + newVersion + ".";
            if (string.IsNullOrEmpty(releasePost))
                this.releaseNoteLinkLabel.Visible = false;
            else {
                this.releaseNoteLinkLabel.Visible = true;
                this.releaseNoteLinkLabel.Links.Add(0, this.releaseNoteLinkLabel.Text.Length, releasePost);
            }
            if (string.IsNullOrEmpty(downloadUrl))
                this.downloadLinkLabel.Visible = false;
            else {
                this.downloadLinkLabel.Links.Add(0, this.downloadLinkLabel.Text.Length, downloadUrl);
                this.downloadLinkLabel.Visible = true;
            }
        }

        private void linkClicked(object sender, LinkLabelLinkClickedEventArgs e) {
            System.Diagnostics.Process.Start(e.Link.LinkData.ToString());
        }
    }
}
