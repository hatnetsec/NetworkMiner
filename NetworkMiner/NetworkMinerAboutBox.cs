using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using System.Reflection;

namespace NetworkMiner {
    partial class NetworkMinerAboutBox : Form {

        private Assembly exeAssembly;

        public NetworkMinerAboutBox(string link, string aboutText) {
            InitializeComponent();
            this.exeAssembly = Assembly.GetEntryAssembly();

            //  Initialize the AboutBox to display the product information from the assembly information.
            //  Change assembly information settings for your application through either:
            //  - Project->Properties->Application->Assembly Information
            //  - AssemblyInfo.cs
            this.Text = String.Format("About {0}", AssemblyTitle);
            this.labelProductName.Text = AssemblyProduct;
            this.labelVersion.Text = String.Format("Version {0}", AssemblyVersion);
            this.labelCopyright.Text = AssemblyCopyright;
            //this.labelCompanyName.Text = AssemblyCompany;
            this.linkLabelHomepage.Text = link;
            this.linkLabelHomepage.Links.Add(0, link.Length, link);
            this.linkLabelHomepage.LinkClicked+=new LinkLabelLinkClickedEventHandler(linkLabelHomepage_Click);
            //this.textBoxDescription.Text = AssemblyDescription;

            if (aboutText != null && aboutText.Length > 0)
                this.textBoxDescription.Text = aboutText;

            this.textBoxDescription.Text += System.Environment.NewLine + System.Environment.NewLine;
            System.Text.StringBuilder protocolString = new System.Text.StringBuilder("Parsed application layer (L7) protocols include: ");
            foreach(PacketParser.ApplicationLayerProtocol l7proto in Enum.GetValues(typeof(PacketParser.ApplicationLayerProtocol))) {
                if (l7proto != PacketParser.ApplicationLayerProtocol.Unknown)
                    protocolString.Append(l7proto + ", ");
            }
            protocolString.Remove(protocolString.Length - 2, 2);
            this.textBoxDescription.Text += protocolString;
        }

        void linkLabelHomepage_Click(object sender, System.Windows.Forms.LinkLabelLinkClickedEventArgs e) {
            string target = e.Link.LinkData as string;
            System.Diagnostics.Process.Start(target);
        }

        #region Assembly Attribute Accessors

        public string AssemblyTitle {
            get {
                // Get all Title attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
                // If there is at least one Title attribute
                if(attributes.Length > 0) {
                    // Select the first one
                    AssemblyTitleAttribute titleAttribute = (AssemblyTitleAttribute)attributes[0];
                    // If it is not an empty string, return it
                    if(titleAttribute.Title != "")
                        return titleAttribute.Title;
                }
                // If there was no Title attribute, or if the Title attribute was the empty string, return the .exe name
                return System.IO.Path.GetFileNameWithoutExtension(this.exeAssembly.CodeBase);
            }
        }

        public string AssemblyVersion {
            get {
                return this.exeAssembly.GetName().Version.ToString();
            }
        }

        public string AssemblyDescription {
            get {
                // Get all Description attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyDescriptionAttribute), false);
                // If there aren't any Description attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Description attribute, return its value
                return ((AssemblyDescriptionAttribute)attributes[0]).Description;
            }
        }

        public string AssemblyProduct {
            get {
                // Get all Product attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyProductAttribute), false);
                // If there aren't any Product attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Product attribute, return its value
                return ((AssemblyProductAttribute)attributes[0]).Product;
            }
        }

        public string AssemblyCopyright {
            get {
                // Get all Copyright attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
                // If there aren't any Copyright attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Copyright attribute, return its value
                return ((AssemblyCopyrightAttribute)attributes[0]).Copyright;
            }
        }

        public string AssemblyCompany {
            get {
                // Get all Company attributes on this assembly
                object[] attributes = this.exeAssembly.GetCustomAttributes(typeof(AssemblyCompanyAttribute), false);
                // If there aren't any Company attributes, return an empty string
                if(attributes.Length == 0)
                    return "";
                // If there is a Company attribute, return its value
                return ((AssemblyCompanyAttribute)attributes[0]).Company;
            }
        }
        #endregion
    }
}
