namespace NetworkMiner {
    partial class NetworkMinerForm {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if(disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(NetworkMinerForm));
            System.Windows.Forms.TreeNode treeNode1 = new System.Windows.Forms.TreeNode("Web browsing tree view is only available in NetworkMiner Professional");
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.toolStripStatusLabel1 = new System.Windows.Forms.ToolStripStatusLabel();
            this.snifferBufferToolStripProgressBar = new System.Windows.Forms.ToolStripProgressBar();
            this.menuStrip1 = new System.Windows.Forms.MenuStrip();
            this.fileToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.readFromPacketCacheToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.receivePcapOverIPToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exportToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.credentialsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.dnsRecordsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.fileInfosToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.hostsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.messagesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.parametersToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.sessionsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.printReportToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.exitToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.settingsToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.downloadRIPEDBToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator2 = new System.Windows.Forms.ToolStripSeparator();
            this.startCapturingToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.stopCapturingToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator3 = new System.Windows.Forms.ToolStripSeparator();
            this.clearGUIToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.resetCapturedDataToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.helpToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.getUpgradeCodeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.signWithLicenseToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.checkForUpdatesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator5 = new System.Windows.Forms.ToolStripSeparator();
            this.aboutNetworkMinerToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.hostMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.expandAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.collapseAllToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyTextToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.selectHostColorMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.removeHostColorToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.parametersContextMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.copyParameterNameToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyParameterValueToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.networkAdaptersComboBox = new System.Windows.Forms.ComboBox();
            this.dataSet1 = new System.Data.DataSet();
            this.openPcapFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.caseFileContextMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.showMetadataToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.openParentFolderToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.removeCaseFileMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.colorDialog1 = new System.Windows.Forms.ColorDialog();
            this.exportDataToFileDialog = new System.Windows.Forms.SaveFileDialog();
            this.openTextFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.browsersMenuStrip = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.setAdvertismentColorToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.setInternetTrackerColorToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator4 = new System.Windows.Forms.ToolStripSeparator();
            this.collapseAllToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.collapseAllButThisToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.expandAllToolStripMenuItem1 = new System.Windows.Forms.ToolStripMenuItem();
            this.findNextToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.selectParentNodeToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.button2 = new System.Windows.Forms.Button();
            this.stopButton = new System.Windows.Forms.Button();
            this.startButton = new System.Windows.Forms.Button();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.tabControl = new System.Windows.Forms.TabControl();
            this.tabPageDetectedHosts = new System.Windows.Forms.TabPage();
            this.networkHostTreeView = new System.Windows.Forms.TreeView();
            this.panel2 = new System.Windows.Forms.Panel();
            this.hostSortingLabel = new System.Windows.Forms.Label();
            this.hostSortOrderComboBox = new System.Windows.Forms.ComboBox();
            this.detectedHostsTreeRebuildButton = new System.Windows.Forms.Button();
            this.tabPageBrowsers = new System.Windows.Forms.TabPage();
            this.browsersSplitContainer = new System.Windows.Forms.SplitContainer();
            this.httpTransactionTreeView = new System.Windows.Forms.TreeView();
            this.httpTransactionPropertyGrid = new System.Windows.Forms.PropertyGrid();
            this.panel4 = new System.Windows.Forms.Panel();
            this.findHttpTransactionTextBox = new System.Windows.Forms.TextBox();
            this.findHttpTransactionCaseSensitiveCheckBox = new System.Windows.Forms.CheckBox();
            this.findHttpTransactionButton = new System.Windows.Forms.Button();
            this.findHttpTransactionLabel = new System.Windows.Forms.Label();
            this.tabPageFiles = new System.Windows.Forms.TabPage();
            this.filesListView = new System.Windows.Forms.ListView();
            this.reconstructedFileInitialFrameNumber = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.filenameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.extensionHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.fileSizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sourceHostHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sourcePortHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.destinationHostHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.destinationPortHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.protocolHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.reconstructedFileTimestampColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.reconstructedFilePathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.detailsHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.filesKeywordFilterControl = new NetworkMiner.KeywordFilterControlForListViewItems();
            this.tabPageImages = new System.Windows.Forms.TabPage();
            this.imagesListView = new System.Windows.Forms.ListView();
            this.tabPageMessages = new System.Windows.Forms.TabPage();
            this.messagesSplitContainer = new System.Windows.Forms.SplitContainer();
            this.messagesListView = new System.Windows.Forms.ListView();
            this.messageFrameColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageSourceHostColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageDestinationHostColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageFromColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageToColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageSubjectColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageProtocolColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageTimestampColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messagesKeywordFilterControl = new NetworkMiner.KeywordFilterControlForListViewItems();
            this.splitContainer3 = new System.Windows.Forms.SplitContainer();
            this.messageAttributeListView = new System.Windows.Forms.ListView();
            this.attributeNameColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.attributeValueColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.splitContainer4 = new System.Windows.Forms.SplitContainer();
            this.messageTextBox = new System.Windows.Forms.TextBox();
            this.messageAttachmentListView = new System.Windows.Forms.ListView();
            this.columnHeader1 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeader2 = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.messageEncodingComboBox = new System.Windows.Forms.ComboBox();
            this.tabPageCredentials = new System.Windows.Forms.TabPage();
            this.credentialsListView = new System.Windows.Forms.ListView();
            this.loggedInClientHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.serverHostHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.protocolStringHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.usernameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.passwordHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.validHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.loginTimestamp = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.panel3 = new System.Windows.Forms.Panel();
            this.showCookiesCheckBox = new System.Windows.Forms.CheckBox();
            this.maskPasswordsCheckBox = new System.Windows.Forms.CheckBox();
            this.showNtlmSspCheckBox = new System.Windows.Forms.CheckBox();
            this.tabPageSessions = new System.Windows.Forms.TabPage();
            this.sessionsListView = new System.Windows.Forms.ListView();
            this.sessionFrameNrColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionClientHostColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionClientPortColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionServerHostColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionServerPortColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionProtocolColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionStartTimeColumnHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.sessionsKeywordFilterControl = new NetworkMiner.KeywordFilterControlForListViewItems();
            this.tabPageDns = new System.Windows.Forms.TabPage();
            this.dnsListView = new System.Windows.Forms.ListView();
            this.columnHeaderDnsFrameNumber = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsTimestamp = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsClient = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsClientPort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsServer = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsServerPort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsIpTtl = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsDnsTtl = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsTransactionId = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsRecordType = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsQuery = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDnsAnswer = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderAlexaTop1M = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.dnsKeywordFilterControl = new NetworkMiner.KeywordFilterControlForListViewItems();
            this.tabPageParameters = new System.Windows.Forms.TabPage();
            this.parametersListView = new System.Windows.Forms.ListView();
            this.parameterName = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterValue = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterFrameNumber = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterSourceHost = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterSourcePort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterDestinationHost = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterDestinationPort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterTimestamp = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parameterDetails = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.parametersKeywordFilterControl = new NetworkMiner.KeywordFilterControlForListViewItems();
            this.tabPageKeywords = new System.Windows.Forms.TabPage();
            this.splitContainer2 = new System.Windows.Forms.SplitContainer();
            this.keywordListBox = new System.Windows.Forms.ListBox();
            this.label1 = new System.Windows.Forms.Label();
            this.addKeywordsFromFileButton = new System.Windows.Forms.Button();
            this.addKeywordButton = new System.Windows.Forms.Button();
            this.keywordTextBox = new System.Windows.Forms.TextBox();
            this.detectedKeywordsListView = new System.Windows.Forms.ListView();
            this.columnHeaderFrameNr = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderTimestamp = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderKeyword = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderContext = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderSourceHost = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderSourcePort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnDestinationHost = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.columnHeaderDestinationPort = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.removeKeywordButton = new System.Windows.Forms.Button();
            this.tabPageCleartext = new System.Windows.Forms.TabPage();
            this.cleartextTextBox = new System.Windows.Forms.TextBox();
            this.panel1 = new System.Windows.Forms.Panel();
            this.changeCleartextDictionaryButton = new System.Windows.Forms.Button();
            this.label2 = new System.Windows.Forms.Label();
            this.cleartextSearchModeComboBox = new System.Windows.Forms.ComboBox();
            this.dictionaryNameLabel = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.button1 = new System.Windows.Forms.Button();
            this.tabPageReceivedFrames = new System.Windows.Forms.TabPage();
            this.framesTreeView = new System.Windows.Forms.TreeView();
            this.ReceivedFramesClearButton = new System.Windows.Forms.Button();
            this.tabPageAnomalyLog = new System.Windows.Forms.TabPage();
            this.anomalyLog = new System.Windows.Forms.TextBox();
            this.clearAnomaliesButton = new System.Windows.Forms.Button();
            this.casePanelBox = new System.Windows.Forms.GroupBox();
            this.casePanelFileListView = new System.Windows.Forms.ListView();
            this.caseFilenameColumn = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.caseMd5Column = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.reloadCaseFilesButton = new System.Windows.Forms.Button();
            this.statusStrip1.SuspendLayout();
            this.menuStrip1.SuspendLayout();
            this.hostMenuStrip.SuspendLayout();
            this.parametersContextMenuStrip.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.dataSet1)).BeginInit();
            this.caseFileContextMenuStrip.SuspendLayout();
            this.browsersMenuStrip.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.tabControl.SuspendLayout();
            this.tabPageDetectedHosts.SuspendLayout();
            this.panel2.SuspendLayout();
            this.tabPageBrowsers.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.browsersSplitContainer)).BeginInit();
            this.browsersSplitContainer.Panel1.SuspendLayout();
            this.browsersSplitContainer.Panel2.SuspendLayout();
            this.browsersSplitContainer.SuspendLayout();
            this.panel4.SuspendLayout();
            this.tabPageFiles.SuspendLayout();
            this.tabPageImages.SuspendLayout();
            this.tabPageMessages.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.messagesSplitContainer)).BeginInit();
            this.messagesSplitContainer.Panel1.SuspendLayout();
            this.messagesSplitContainer.Panel2.SuspendLayout();
            this.messagesSplitContainer.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer3)).BeginInit();
            this.splitContainer3.Panel1.SuspendLayout();
            this.splitContainer3.Panel2.SuspendLayout();
            this.splitContainer3.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer4)).BeginInit();
            this.splitContainer4.Panel1.SuspendLayout();
            this.splitContainer4.Panel2.SuspendLayout();
            this.splitContainer4.SuspendLayout();
            this.tabPageCredentials.SuspendLayout();
            this.panel3.SuspendLayout();
            this.tabPageSessions.SuspendLayout();
            this.tabPageDns.SuspendLayout();
            this.tabPageParameters.SuspendLayout();
            this.tabPageKeywords.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer2)).BeginInit();
            this.splitContainer2.Panel1.SuspendLayout();
            this.splitContainer2.Panel2.SuspendLayout();
            this.splitContainer2.SuspendLayout();
            this.tabPageCleartext.SuspendLayout();
            this.panel1.SuspendLayout();
            this.tabPageReceivedFrames.SuspendLayout();
            this.tabPageAnomalyLog.SuspendLayout();
            this.casePanelBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // statusStrip1
            // 
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.toolStripStatusLabel1,
            this.snifferBufferToolStripProgressBar});
            this.statusStrip1.Location = new System.Drawing.Point(0, 425);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(690, 22);
            this.statusStrip1.TabIndex = 0;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // toolStripStatusLabel1
            // 
            this.toolStripStatusLabel1.Name = "toolStripStatusLabel1";
            this.toolStripStatusLabel1.Size = new System.Drawing.Size(141, 17);
            this.toolStripStatusLabel1.Text = "Buffered Frames to Parse:";
            // 
            // snifferBufferToolStripProgressBar
            // 
            this.snifferBufferToolStripProgressBar.ForeColor = System.Drawing.Color.Purple;
            this.snifferBufferToolStripProgressBar.Name = "snifferBufferToolStripProgressBar";
            this.snifferBufferToolStripProgressBar.Size = new System.Drawing.Size(200, 16);
            this.snifferBufferToolStripProgressBar.Step = 1;
            this.snifferBufferToolStripProgressBar.Style = System.Windows.Forms.ProgressBarStyle.Continuous;
            // 
            // menuStrip1
            // 
            this.menuStrip1.BackgroundImageLayout = System.Windows.Forms.ImageLayout.None;
            this.menuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.fileToolStripMenuItem,
            this.toolsToolStripMenuItem,
            this.helpToolStripMenuItem});
            this.menuStrip1.Location = new System.Drawing.Point(0, 0);
            this.menuStrip1.Name = "menuStrip1";
            this.menuStrip1.Size = new System.Drawing.Size(690, 24);
            this.menuStrip1.TabIndex = 1;
            this.menuStrip1.Text = "menuStrip1";
            // 
            // fileToolStripMenuItem
            // 
            this.fileToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.openToolStripMenuItem,
            this.readFromPacketCacheToolStripMenuItem,
            this.receivePcapOverIPToolStripMenuItem,
            this.exportToolStripMenuItem,
            this.printReportToolStripMenuItem,
            this.exitToolStripMenuItem});
            this.fileToolStripMenuItem.Name = "fileToolStripMenuItem";
            this.fileToolStripMenuItem.Size = new System.Drawing.Size(37, 20);
            this.fileToolStripMenuItem.Text = "&File";
            // 
            // openToolStripMenuItem
            // 
            this.openToolStripMenuItem.Image = global::NetworkMiner.Properties.Resources.openHS;
            this.openToolStripMenuItem.Name = "openToolStripMenuItem";
            this.openToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.O)));
            this.openToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.openToolStripMenuItem.Text = "&Open";
            this.openToolStripMenuItem.Click += new System.EventHandler(this.openToolStripMenuItem_Click);
            // 
            // readFromPacketCacheToolStripMenuItem
            // 
            this.readFromPacketCacheToolStripMenuItem.Image = global::NetworkMiner.Properties.Resources.PacketCache_16x16;
            this.readFromPacketCacheToolStripMenuItem.Name = "readFromPacketCacheToolStripMenuItem";
            this.readFromPacketCacheToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.readFromPacketCacheToolStripMenuItem.Text = "Read from Packet&Cache";
            this.readFromPacketCacheToolStripMenuItem.Click += new System.EventHandler(this.readFromPacketCacheToolStripMenuItem_Click);
            // 
            // receivePcapOverIPToolStripMenuItem
            // 
            this.receivePcapOverIPToolStripMenuItem.Name = "receivePcapOverIPToolStripMenuItem";
            this.receivePcapOverIPToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.R)));
            this.receivePcapOverIPToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.receivePcapOverIPToolStripMenuItem.Text = "&Receive Pcap over IP";
            this.receivePcapOverIPToolStripMenuItem.Click += new System.EventHandler(this.receivePcapOverIPToolStripMenuItem_Click);
            // 
            // exportToolStripMenuItem
            // 
            this.exportToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.credentialsToolStripMenuItem,
            this.dnsRecordsToolStripMenuItem,
            this.fileInfosToolStripMenuItem,
            this.hostsToolStripMenuItem,
            this.messagesToolStripMenuItem,
            this.parametersToolStripMenuItem,
            this.sessionsToolStripMenuItem});
            this.exportToolStripMenuItem.Enabled = false;
            this.exportToolStripMenuItem.Name = "exportToolStripMenuItem";
            this.exportToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.exportToolStripMenuItem.Text = "&Export to File";
            this.exportToolStripMenuItem.Visible = false;
            // 
            // credentialsToolStripMenuItem
            // 
            this.credentialsToolStripMenuItem.Name = "credentialsToolStripMenuItem";
            this.credentialsToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.credentialsToolStripMenuItem.Text = "Credentials";
            this.credentialsToolStripMenuItem.Click += new System.EventHandler(this.credentialsToolStripMenuItem_Click);
            // 
            // dnsRecordsToolStripMenuItem
            // 
            this.dnsRecordsToolStripMenuItem.Name = "dnsRecordsToolStripMenuItem";
            this.dnsRecordsToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.dnsRecordsToolStripMenuItem.Text = "DNS";
            this.dnsRecordsToolStripMenuItem.Click += new System.EventHandler(this.dnsRecordsToolStripMenuItem_Click);
            // 
            // fileInfosToolStripMenuItem
            // 
            this.fileInfosToolStripMenuItem.Name = "fileInfosToolStripMenuItem";
            this.fileInfosToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.fileInfosToolStripMenuItem.Text = "File MetaData";
            this.fileInfosToolStripMenuItem.Click += new System.EventHandler(this.fileInfosToolStripMenuItem_Click);
            // 
            // hostsToolStripMenuItem
            // 
            this.hostsToolStripMenuItem.Name = "hostsToolStripMenuItem";
            this.hostsToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.hostsToolStripMenuItem.Text = "Hosts";
            this.hostsToolStripMenuItem.Click += new System.EventHandler(this.hostsToolStripMenuItem_Click);
            // 
            // messagesToolStripMenuItem
            // 
            this.messagesToolStripMenuItem.Name = "messagesToolStripMenuItem";
            this.messagesToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.messagesToolStripMenuItem.Text = "Messages";
            this.messagesToolStripMenuItem.Click += new System.EventHandler(this.messagesToolStripMenuItem_Click);
            // 
            // parametersToolStripMenuItem
            // 
            this.parametersToolStripMenuItem.Name = "parametersToolStripMenuItem";
            this.parametersToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.parametersToolStripMenuItem.Text = "Parameters";
            this.parametersToolStripMenuItem.Click += new System.EventHandler(this.parametersToolStripMenuItem_Click);
            // 
            // sessionsToolStripMenuItem
            // 
            this.sessionsToolStripMenuItem.Name = "sessionsToolStripMenuItem";
            this.sessionsToolStripMenuItem.Size = new System.Drawing.Size(146, 22);
            this.sessionsToolStripMenuItem.Text = "Sessions";
            this.sessionsToolStripMenuItem.Click += new System.EventHandler(this.sessionsToolStripMenuItem_Click);
            // 
            // printReportToolStripMenuItem
            // 
            this.printReportToolStripMenuItem.Name = "printReportToolStripMenuItem";
            this.printReportToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.printReportToolStripMenuItem.Text = "&Print Report";
            this.printReportToolStripMenuItem.Visible = false;
            this.printReportToolStripMenuItem.Click += new System.EventHandler(this.printReportToolStripMenuItem_Click);
            // 
            // exitToolStripMenuItem
            // 
            this.exitToolStripMenuItem.Name = "exitToolStripMenuItem";
            this.exitToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Alt | System.Windows.Forms.Keys.F4)));
            this.exitToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.exitToolStripMenuItem.Text = "E&xit";
            this.exitToolStripMenuItem.Click += new System.EventHandler(this.exitToolStripMenuItem_Click);
            // 
            // toolsToolStripMenuItem
            // 
            this.toolsToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.settingsToolStripMenuItem,
            this.downloadRIPEDBToolStripMenuItem,
            this.toolStripSeparator2,
            this.startCapturingToolStripMenuItem,
            this.stopCapturingToolStripMenuItem,
            this.toolStripSeparator3,
            this.clearGUIToolStripMenuItem,
            this.resetCapturedDataToolStripMenuItem});
            this.toolsToolStripMenuItem.Name = "toolsToolStripMenuItem";
            this.toolsToolStripMenuItem.Size = new System.Drawing.Size(47, 20);
            this.toolsToolStripMenuItem.Text = "&Tools";
            // 
            // settingsToolStripMenuItem
            // 
            this.settingsToolStripMenuItem.Enabled = false;
            this.settingsToolStripMenuItem.Name = "settingsToolStripMenuItem";
            this.settingsToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.settingsToolStripMenuItem.Text = "&Settings";
            this.settingsToolStripMenuItem.Visible = false;
            // 
            // downloadRIPEDBToolStripMenuItem
            // 
            this.downloadRIPEDBToolStripMenuItem.Enabled = false;
            this.downloadRIPEDBToolStripMenuItem.Name = "downloadRIPEDBToolStripMenuItem";
            this.downloadRIPEDBToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.downloadRIPEDBToolStripMenuItem.Text = "Download RIPE DB";
            this.downloadRIPEDBToolStripMenuItem.Visible = false;
            // 
            // toolStripSeparator2
            // 
            this.toolStripSeparator2.Name = "toolStripSeparator2";
            this.toolStripSeparator2.Size = new System.Drawing.Size(234, 6);
            this.toolStripSeparator2.Visible = false;
            // 
            // startCapturingToolStripMenuItem
            // 
            this.startCapturingToolStripMenuItem.Enabled = false;
            this.startCapturingToolStripMenuItem.Image = global::NetworkMiner.Properties.Resources.PlayHS;
            this.startCapturingToolStripMenuItem.Name = "startCapturingToolStripMenuItem";
            this.startCapturingToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F5;
            this.startCapturingToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.startCapturingToolStripMenuItem.Text = "&Start Capturing";
            this.startCapturingToolStripMenuItem.Click += new System.EventHandler(this.startButton_Click);
            // 
            // stopCapturingToolStripMenuItem
            // 
            this.stopCapturingToolStripMenuItem.Image = global::NetworkMiner.Properties.Resources.StopHS;
            this.stopCapturingToolStripMenuItem.Name = "stopCapturingToolStripMenuItem";
            this.stopCapturingToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F8;
            this.stopCapturingToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.stopCapturingToolStripMenuItem.Text = "S&top Capturing";
            this.stopCapturingToolStripMenuItem.Click += new System.EventHandler(this.stopButton_Click);
            // 
            // toolStripSeparator3
            // 
            this.toolStripSeparator3.Name = "toolStripSeparator3";
            this.toolStripSeparator3.Size = new System.Drawing.Size(234, 6);
            // 
            // clearGUIToolStripMenuItem
            // 
            this.clearGUIToolStripMenuItem.Image = ((System.Drawing.Image)(resources.GetObject("clearGUIToolStripMenuItem.Image")));
            this.clearGUIToolStripMenuItem.Name = "clearGUIToolStripMenuItem";
            this.clearGUIToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.N)));
            this.clearGUIToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.clearGUIToolStripMenuItem.Text = "Clear GUI";
            this.clearGUIToolStripMenuItem.Click += new System.EventHandler(this.clearGUIToolStripMenuItem_Click);
            // 
            // resetCapturedDataToolStripMenuItem
            // 
            this.resetCapturedDataToolStripMenuItem.Image = global::NetworkMiner.Properties.Resources.DeleteFolderHS;
            this.resetCapturedDataToolStripMenuItem.Name = "resetCapturedDataToolStripMenuItem";
            this.resetCapturedDataToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Delete)));
            this.resetCapturedDataToolStripMenuItem.Size = new System.Drawing.Size(237, 22);
            this.resetCapturedDataToolStripMenuItem.Text = "&Delete Captured Data";
            this.resetCapturedDataToolStripMenuItem.ToolTipText = "Clears the GUI and removes all files in AssembledFiles and Captures directories";
            this.resetCapturedDataToolStripMenuItem.Click += new System.EventHandler(this.resetCapturedDataToolStripMenuItem_Click);
            // 
            // helpToolStripMenuItem
            // 
            this.helpToolStripMenuItem.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.getUpgradeCodeToolStripMenuItem,
            this.signWithLicenseToolStripMenuItem,
            this.toolStripSeparator1,
            this.checkForUpdatesToolStripMenuItem,
            this.toolStripSeparator5,
            this.aboutNetworkMinerToolStripMenuItem});
            this.helpToolStripMenuItem.Name = "helpToolStripMenuItem";
            this.helpToolStripMenuItem.Size = new System.Drawing.Size(44, 20);
            this.helpToolStripMenuItem.Text = "&Help";
            // 
            // getUpgradeCodeToolStripMenuItem
            // 
            this.getUpgradeCodeToolStripMenuItem.Enabled = false;
            this.getUpgradeCodeToolStripMenuItem.Name = "getUpgradeCodeToolStripMenuItem";
            this.getUpgradeCodeToolStripMenuItem.Size = new System.Drawing.Size(186, 22);
            this.getUpgradeCodeToolStripMenuItem.Text = "Get &Upgrade Code";
            this.getUpgradeCodeToolStripMenuItem.Visible = false;
            this.getUpgradeCodeToolStripMenuItem.Click += new System.EventHandler(this.getUpgradeCodeToolStripMenuItem_Click);
            // 
            // signWithLicenseToolStripMenuItem
            // 
            this.signWithLicenseToolStripMenuItem.Enabled = false;
            this.signWithLicenseToolStripMenuItem.Name = "signWithLicenseToolStripMenuItem";
            this.signWithLicenseToolStripMenuItem.Size = new System.Drawing.Size(186, 22);
            this.signWithLicenseToolStripMenuItem.Text = "&Authenticate";
            this.signWithLicenseToolStripMenuItem.Visible = false;
            this.signWithLicenseToolStripMenuItem.Click += new System.EventHandler(this.signWithLicenseToolStripMenuItem_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(183, 6);
            this.toolStripSeparator1.Visible = false;
            // 
            // checkForUpdatesToolStripMenuItem
            // 
            this.checkForUpdatesToolStripMenuItem.Name = "checkForUpdatesToolStripMenuItem";
            this.checkForUpdatesToolStripMenuItem.Size = new System.Drawing.Size(186, 22);
            this.checkForUpdatesToolStripMenuItem.Text = "&Check for Updates";
            this.checkForUpdatesToolStripMenuItem.Click += new System.EventHandler(this.checkForUpdatesToolStripMenuItem_Click);
            // 
            // toolStripSeparator5
            // 
            this.toolStripSeparator5.Name = "toolStripSeparator5";
            this.toolStripSeparator5.Size = new System.Drawing.Size(183, 6);
            // 
            // aboutNetworkMinerToolStripMenuItem
            // 
            this.aboutNetworkMinerToolStripMenuItem.Name = "aboutNetworkMinerToolStripMenuItem";
            this.aboutNetworkMinerToolStripMenuItem.Size = new System.Drawing.Size(186, 22);
            this.aboutNetworkMinerToolStripMenuItem.Text = "About &NetworkMiner";
            this.aboutNetworkMinerToolStripMenuItem.Click += new System.EventHandler(this.aboutNetworkMinerToolStripMenuItem_Click);
            // 
            // hostMenuStrip
            // 
            this.hostMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.expandAllToolStripMenuItem,
            this.collapseAllToolStripMenuItem,
            this.copyTextToolStripMenuItem,
            this.selectHostColorMenuItem,
            this.removeHostColorToolStripMenuItem});
            this.hostMenuStrip.Name = "hostColorMenuStrip";
            this.hostMenuStrip.Size = new System.Drawing.Size(178, 114);
            this.hostMenuStrip.Opening += new System.ComponentModel.CancelEventHandler(this.hostColorMenuStrip_Opening);
            // 
            // expandAllToolStripMenuItem
            // 
            this.expandAllToolStripMenuItem.Name = "expandAllToolStripMenuItem";
            this.expandAllToolStripMenuItem.Size = new System.Drawing.Size(177, 22);
            this.expandAllToolStripMenuItem.Text = "Expand All";
            this.expandAllToolStripMenuItem.Click += new System.EventHandler(this.expandAllToolStripMenuItem_Click);
            // 
            // collapseAllToolStripMenuItem
            // 
            this.collapseAllToolStripMenuItem.Name = "collapseAllToolStripMenuItem";
            this.collapseAllToolStripMenuItem.Size = new System.Drawing.Size(177, 22);
            this.collapseAllToolStripMenuItem.Text = "Collapse All";
            this.collapseAllToolStripMenuItem.Click += new System.EventHandler(this.collapseAllToolStripMenuItem_Click);
            // 
            // copyTextToolStripMenuItem
            // 
            this.copyTextToolStripMenuItem.Name = "copyTextToolStripMenuItem";
            this.copyTextToolStripMenuItem.Size = new System.Drawing.Size(177, 22);
            this.copyTextToolStripMenuItem.Text = "Copy Text";
            this.copyTextToolStripMenuItem.Click += new System.EventHandler(this.copyTextToolStripMenuItem_Click);
            // 
            // selectHostColorMenuItem
            // 
            this.selectHostColorMenuItem.Name = "selectHostColorMenuItem";
            this.selectHostColorMenuItem.Size = new System.Drawing.Size(177, 22);
            this.selectHostColorMenuItem.Text = "Set Host Color";
            this.selectHostColorMenuItem.Click += new System.EventHandler(this.selectHostColorMenuItem_Click);
            // 
            // removeHostColorToolStripMenuItem
            // 
            this.removeHostColorToolStripMenuItem.Enabled = false;
            this.removeHostColorToolStripMenuItem.Name = "removeHostColorToolStripMenuItem";
            this.removeHostColorToolStripMenuItem.Size = new System.Drawing.Size(177, 22);
            this.removeHostColorToolStripMenuItem.Text = "Remove Host Color";
            this.removeHostColorToolStripMenuItem.Click += new System.EventHandler(this.removeHostColorToolStripMenuItem_Click);
            // 
            // parametersContextMenuStrip
            // 
            this.parametersContextMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.copyParameterNameToolStripMenuItem,
            this.copyParameterValueToolStripMenuItem});
            this.parametersContextMenuStrip.Name = "parametersContextMenuStrip";
            this.parametersContextMenuStrip.Size = new System.Drawing.Size(193, 48);
            this.parametersContextMenuStrip.Opening += new System.ComponentModel.CancelEventHandler(this.parametersContextMenuStrip_Opening);
            // 
            // copyParameterNameToolStripMenuItem
            // 
            this.copyParameterNameToolStripMenuItem.Name = "copyParameterNameToolStripMenuItem";
            this.copyParameterNameToolStripMenuItem.Size = new System.Drawing.Size(192, 22);
            this.copyParameterNameToolStripMenuItem.Text = "Copy parameter name";
            this.copyParameterNameToolStripMenuItem.Click += new System.EventHandler(this.copyParameterNameToolStripMenuItem_Click);
            // 
            // copyParameterValueToolStripMenuItem
            // 
            this.copyParameterValueToolStripMenuItem.Name = "copyParameterValueToolStripMenuItem";
            this.copyParameterValueToolStripMenuItem.Size = new System.Drawing.Size(192, 22);
            this.copyParameterValueToolStripMenuItem.Text = "Copy parameter value";
            this.copyParameterValueToolStripMenuItem.Click += new System.EventHandler(this.copyParameterValueToolStripMenuItem_Click);
            // 
            // networkAdaptersComboBox
            // 
            this.networkAdaptersComboBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.networkAdaptersComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.networkAdaptersComboBox.FormattingEnabled = true;
            this.networkAdaptersComboBox.Location = new System.Drawing.Point(0, 27);
            this.networkAdaptersComboBox.Name = "networkAdaptersComboBox";
            this.networkAdaptersComboBox.Size = new System.Drawing.Size(574, 21);
            this.networkAdaptersComboBox.TabIndex = 7;
            this.networkAdaptersComboBox.SelectedIndexChanged += new System.EventHandler(this.networkAdaptersComboBox_SelectedIndexChanged);
            // 
            // dataSet1
            // 
            this.dataSet1.DataSetName = "NewDataSet";
            // 
            // openPcapFileDialog
            // 
            this.openPcapFileDialog.FileName = "openPcapFileDialog";
            this.openPcapFileDialog.FileOk += new System.ComponentModel.CancelEventHandler(this.openFileDialog1_FileOk);
            // 
            // caseFileContextMenuStrip
            // 
            this.caseFileContextMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.showMetadataToolStripMenuItem,
            this.openParentFolderToolStripMenuItem,
            this.removeCaseFileMenuItem,
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem});
            this.caseFileContextMenuStrip.Name = "caseFileContextMenuStrip";
            this.caseFileContextMenuStrip.Size = new System.Drawing.Size(304, 92);
            // 
            // showMetadataToolStripMenuItem
            // 
            this.showMetadataToolStripMenuItem.Name = "showMetadataToolStripMenuItem";
            this.showMetadataToolStripMenuItem.Size = new System.Drawing.Size(303, 22);
            this.showMetadataToolStripMenuItem.Text = "Show Metadata";
            this.showMetadataToolStripMenuItem.Click += new System.EventHandler(this.showMetadataToolStripMenuItem_Click);
            // 
            // openParentFolderToolStripMenuItem
            // 
            this.openParentFolderToolStripMenuItem.Name = "openParentFolderToolStripMenuItem";
            this.openParentFolderToolStripMenuItem.Size = new System.Drawing.Size(303, 22);
            this.openParentFolderToolStripMenuItem.Text = "Open parent folder";
            this.openParentFolderToolStripMenuItem.Click += new System.EventHandler(this.openParentFolderToolStripMenuItem_Click);
            // 
            // removeCaseFileMenuItem
            // 
            this.removeCaseFileMenuItem.Name = "removeCaseFileMenuItem";
            this.removeCaseFileMenuItem.Size = new System.Drawing.Size(303, 22);
            this.removeCaseFileMenuItem.Text = "Remove selected files from Case";
            this.removeCaseFileMenuItem.Click += new System.EventHandler(this.removeCaseFileMenuItem_Click);
            // 
            // removeSelectedFilesAndReloadCaseFilesToolStripMenuItem
            // 
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem.Name = "removeSelectedFilesAndReloadCaseFilesToolStripMenuItem";
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem.Size = new System.Drawing.Size(303, 22);
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem.Text = "Remove selected files and Reload Case Files";
            this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem.Click += new System.EventHandler(this.removeSelectedFilesAndReloadCaseFilesToolStripMenuItem_Click);
            // 
            // exportDataToFileDialog
            // 
            this.exportDataToFileDialog.FileName = "export.json";
            this.exportDataToFileDialog.Filter = "CASE|*.json|CSV (comma-separated values)|*.csv|XML|*.xml|All files|*.*";
            this.exportDataToFileDialog.Title = "Export to CASE, CSV or XML file";
            // 
            // openTextFileDialog
            // 
            this.openTextFileDialog.DefaultExt = "*.txt";
            this.openTextFileDialog.FileName = "*.txt";
            this.openTextFileDialog.Filter = "Text files|*.txt|All files|*.*";
            // 
            // browsersMenuStrip
            // 
            this.browsersMenuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.setAdvertismentColorToolStripMenuItem,
            this.setInternetTrackerColorToolStripMenuItem,
            this.toolStripSeparator4,
            this.collapseAllToolStripMenuItem1,
            this.collapseAllButThisToolStripMenuItem,
            this.expandAllToolStripMenuItem1,
            this.findNextToolStripMenuItem,
            this.selectParentNodeToolStripMenuItem});
            this.browsersMenuStrip.Name = "browsersMenuStrip";
            this.browsersMenuStrip.Size = new System.Drawing.Size(224, 164);
            // 
            // setAdvertismentColorToolStripMenuItem
            // 
            this.setAdvertismentColorToolStripMenuItem.Name = "setAdvertismentColorToolStripMenuItem";
            this.setAdvertismentColorToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.setAdvertismentColorToolStripMenuItem.Text = "Set Advertisment Color";
            this.setAdvertismentColorToolStripMenuItem.Click += new System.EventHandler(this.setAdvertismentColorToolStripMenuItem_Click);
            // 
            // setInternetTrackerColorToolStripMenuItem
            // 
            this.setInternetTrackerColorToolStripMenuItem.Name = "setInternetTrackerColorToolStripMenuItem";
            this.setInternetTrackerColorToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.setInternetTrackerColorToolStripMenuItem.Text = "Set Internet Tracker Color";
            this.setInternetTrackerColorToolStripMenuItem.Click += new System.EventHandler(this.setInternetTrackerColorToolStripMenuItem_Click);
            // 
            // toolStripSeparator4
            // 
            this.toolStripSeparator4.Name = "toolStripSeparator4";
            this.toolStripSeparator4.Size = new System.Drawing.Size(220, 6);
            // 
            // collapseAllToolStripMenuItem1
            // 
            this.collapseAllToolStripMenuItem1.Name = "collapseAllToolStripMenuItem1";
            this.collapseAllToolStripMenuItem1.Size = new System.Drawing.Size(223, 22);
            this.collapseAllToolStripMenuItem1.Text = "Collapse All";
            this.collapseAllToolStripMenuItem1.Click += new System.EventHandler(this.collapseAllToolStripMenuItem1_Click);
            // 
            // collapseAllButThisToolStripMenuItem
            // 
            this.collapseAllButThisToolStripMenuItem.Name = "collapseAllButThisToolStripMenuItem";
            this.collapseAllButThisToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.collapseAllButThisToolStripMenuItem.Text = "Collapse All But Selected";
            this.collapseAllButThisToolStripMenuItem.Click += new System.EventHandler(this.collapseAllButThisToolStripMenuItem_Click);
            // 
            // expandAllToolStripMenuItem1
            // 
            this.expandAllToolStripMenuItem1.Name = "expandAllToolStripMenuItem1";
            this.expandAllToolStripMenuItem1.Size = new System.Drawing.Size(223, 22);
            this.expandAllToolStripMenuItem1.Text = "Expand All";
            this.expandAllToolStripMenuItem1.Click += new System.EventHandler(this.expandAllToolStripMenuItem1_Click);
            // 
            // findNextToolStripMenuItem
            // 
            this.findNextToolStripMenuItem.Name = "findNextToolStripMenuItem";
            this.findNextToolStripMenuItem.ShortcutKeys = System.Windows.Forms.Keys.F3;
            this.findNextToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.findNextToolStripMenuItem.Text = "Find Next";
            this.findNextToolStripMenuItem.Click += new System.EventHandler(this.findNextToolStripMenuItem_Click);
            // 
            // selectParentNodeToolStripMenuItem
            // 
            this.selectParentNodeToolStripMenuItem.Name = "selectParentNodeToolStripMenuItem";
            this.selectParentNodeToolStripMenuItem.ShortcutKeys = ((System.Windows.Forms.Keys)((System.Windows.Forms.Keys.Control | System.Windows.Forms.Keys.Up)));
            this.selectParentNodeToolStripMenuItem.Size = new System.Drawing.Size(223, 22);
            this.selectParentNodeToolStripMenuItem.Text = "Select Parent Node";
            this.selectParentNodeToolStripMenuItem.Click += new System.EventHandler(this.selectParentNodeToolStripMenuItem_Click);
            // 
            // button2
            // 
            this.button2.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.button2.Enabled = false;
            this.button2.Image = global::NetworkMiner.Properties.Resources.Filter2HS;
            this.button2.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.button2.Location = new System.Drawing.Point(522, 27);
            this.button2.Name = "button2";
            this.button2.Size = new System.Drawing.Size(52, 21);
            this.button2.TabIndex = 8;
            this.button2.Text = "Filter";
            this.button2.TextAlign = System.Drawing.ContentAlignment.BottomRight;
            this.button2.UseVisualStyleBackColor = true;
            this.button2.Visible = false;
            // 
            // stopButton
            // 
            this.stopButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.stopButton.Image = global::NetworkMiner.Properties.Resources.StopHS;
            this.stopButton.ImageAlign = System.Drawing.ContentAlignment.BottomLeft;
            this.stopButton.Location = new System.Drawing.Point(638, 27);
            this.stopButton.Name = "stopButton";
            this.stopButton.Size = new System.Drawing.Size(52, 21);
            this.stopButton.TabIndex = 4;
            this.stopButton.Text = "Stop";
            this.stopButton.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.stopButton.UseVisualStyleBackColor = true;
            this.stopButton.Click += new System.EventHandler(this.stopButton_Click);
            // 
            // startButton
            // 
            this.startButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.startButton.Enabled = false;
            this.startButton.Image = global::NetworkMiner.Properties.Resources.PlayHS;
            this.startButton.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.startButton.Location = new System.Drawing.Point(580, 27);
            this.startButton.Name = "startButton";
            this.startButton.Size = new System.Drawing.Size(52, 21);
            this.startButton.TabIndex = 2;
            this.startButton.Text = "Start";
            this.startButton.TextAlign = System.Drawing.ContentAlignment.BottomRight;
            this.startButton.UseVisualStyleBackColor = true;
            this.startButton.Click += new System.EventHandler(this.startButton_Click);
            // 
            // splitContainer1
            // 
            this.splitContainer1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.splitContainer1.BackColor = System.Drawing.SystemColors.Control;
            this.splitContainer1.Location = new System.Drawing.Point(0, 54);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.tabControl);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.casePanelBox);
            this.splitContainer1.Size = new System.Drawing.Size(690, 368);
            this.splitContainer1.SplitterDistance = 570;
            this.splitContainer1.TabIndex = 10;
            // 
            // tabControl
            // 
            this.tabControl.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.tabControl.Controls.Add(this.tabPageDetectedHosts);
            this.tabControl.Controls.Add(this.tabPageBrowsers);
            this.tabControl.Controls.Add(this.tabPageFiles);
            this.tabControl.Controls.Add(this.tabPageImages);
            this.tabControl.Controls.Add(this.tabPageMessages);
            this.tabControl.Controls.Add(this.tabPageCredentials);
            this.tabControl.Controls.Add(this.tabPageSessions);
            this.tabControl.Controls.Add(this.tabPageDns);
            this.tabControl.Controls.Add(this.tabPageParameters);
            this.tabControl.Controls.Add(this.tabPageKeywords);
            this.tabControl.Controls.Add(this.tabPageCleartext);
            this.tabControl.Controls.Add(this.tabPageReceivedFrames);
            this.tabControl.Controls.Add(this.tabPageAnomalyLog);
            this.tabControl.ItemSize = new System.Drawing.Size(16, 18);
            this.tabControl.Location = new System.Drawing.Point(3, 3);
            this.tabControl.Multiline = true;
            this.tabControl.Name = "tabControl";
            this.tabControl.Padding = new System.Drawing.Point(5, 3);
            this.tabControl.SelectedIndex = 0;
            this.tabControl.Size = new System.Drawing.Size(564, 362);
            this.tabControl.TabIndex = 6;
            // 
            // tabPageDetectedHosts
            // 
            this.tabPageDetectedHosts.Controls.Add(this.networkHostTreeView);
            this.tabPageDetectedHosts.Controls.Add(this.panel2);
            this.tabPageDetectedHosts.Location = new System.Drawing.Point(4, 40);
            this.tabPageDetectedHosts.Name = "tabPageDetectedHosts";
            this.tabPageDetectedHosts.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageDetectedHosts.Size = new System.Drawing.Size(556, 318);
            this.tabPageDetectedHosts.TabIndex = 2;
            this.tabPageDetectedHosts.Text = "Hosts";
            this.tabPageDetectedHosts.UseVisualStyleBackColor = true;
            // 
            // networkHostTreeView
            // 
            this.networkHostTreeView.ContextMenuStrip = this.hostMenuStrip;
            this.networkHostTreeView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.networkHostTreeView.Location = new System.Drawing.Point(3, 30);
            this.networkHostTreeView.Name = "networkHostTreeView";
            this.networkHostTreeView.Size = new System.Drawing.Size(550, 285);
            this.networkHostTreeView.TabIndex = 0;
            this.networkHostTreeView.MouseDown += new System.Windows.Forms.MouseEventHandler(this.networkHostTreeView_MouseDown);
            // 
            // panel2
            // 
            this.panel2.Controls.Add(this.hostSortingLabel);
            this.panel2.Controls.Add(this.hostSortOrderComboBox);
            this.panel2.Controls.Add(this.detectedHostsTreeRebuildButton);
            this.panel2.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel2.Location = new System.Drawing.Point(3, 3);
            this.panel2.Name = "panel2";
            this.panel2.Size = new System.Drawing.Size(550, 27);
            this.panel2.TabIndex = 3;
            // 
            // hostSortingLabel
            // 
            this.hostSortingLabel.AutoSize = true;
            this.hostSortingLabel.Location = new System.Drawing.Point(3, 7);
            this.hostSortingLabel.Name = "hostSortingLabel";
            this.hostSortingLabel.Size = new System.Drawing.Size(79, 13);
            this.hostSortingLabel.TabIndex = 3;
            this.hostSortingLabel.Text = "Sort Hosts On: ";
            // 
            // hostSortOrderComboBox
            // 
            this.hostSortOrderComboBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.hostSortOrderComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.hostSortOrderComboBox.FormattingEnabled = true;
            this.hostSortOrderComboBox.Items.AddRange(new object[] {
            "IP Address (ascending)",
            "MAC Address  (ascending)",
            "Hostname",
            "Sent Packets (descending)",
            "Received Packets (descending)",
            "Sent Bytes (descending)",
            "Received Bytes (descending)",
            "Number of Open TCP Ports (descending)",
            "Operating System",
            "Router Hops Distance (ascending)"});
            this.hostSortOrderComboBox.Location = new System.Drawing.Point(88, 3);
            this.hostSortOrderComboBox.Name = "hostSortOrderComboBox";
            this.hostSortOrderComboBox.Size = new System.Drawing.Size(298, 21);
            this.hostSortOrderComboBox.TabIndex = 2;
            this.hostSortOrderComboBox.SelectedIndexChanged += new System.EventHandler(this.hostSortOrderComboBox_SelectedIndexChanged);
            // 
            // detectedHostsTreeRebuildButton
            // 
            this.detectedHostsTreeRebuildButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.detectedHostsTreeRebuildButton.Location = new System.Drawing.Point(392, 3);
            this.detectedHostsTreeRebuildButton.Name = "detectedHostsTreeRebuildButton";
            this.detectedHostsTreeRebuildButton.Size = new System.Drawing.Size(155, 21);
            this.detectedHostsTreeRebuildButton.TabIndex = 1;
            this.detectedHostsTreeRebuildButton.Text = "Sort and Refresh";
            this.detectedHostsTreeRebuildButton.UseVisualStyleBackColor = true;
            this.detectedHostsTreeRebuildButton.Click += new System.EventHandler(this.detectedHostsTreeRebuildButton_Click);
            // 
            // tabPageBrowsers
            // 
            this.tabPageBrowsers.Controls.Add(this.browsersSplitContainer);
            this.tabPageBrowsers.Controls.Add(this.panel4);
            this.tabPageBrowsers.Location = new System.Drawing.Point(4, 40);
            this.tabPageBrowsers.Name = "tabPageBrowsers";
            this.tabPageBrowsers.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageBrowsers.Size = new System.Drawing.Size(556, 318);
            this.tabPageBrowsers.TabIndex = 13;
            this.tabPageBrowsers.Text = "Browsers";
            this.tabPageBrowsers.UseVisualStyleBackColor = true;
            // 
            // browsersSplitContainer
            // 
            this.browsersSplitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.browsersSplitContainer.Location = new System.Drawing.Point(3, 25);
            this.browsersSplitContainer.Name = "browsersSplitContainer";
            // 
            // browsersSplitContainer.Panel1
            // 
            this.browsersSplitContainer.Panel1.Controls.Add(this.httpTransactionTreeView);
            // 
            // browsersSplitContainer.Panel2
            // 
            this.browsersSplitContainer.Panel2.Controls.Add(this.httpTransactionPropertyGrid);
            this.browsersSplitContainer.Size = new System.Drawing.Size(550, 290);
            this.browsersSplitContainer.SplitterDistance = 395;
            this.browsersSplitContainer.TabIndex = 4;
            // 
            // httpTransactionTreeView
            // 
            this.httpTransactionTreeView.ContextMenuStrip = this.browsersMenuStrip;
            this.httpTransactionTreeView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.httpTransactionTreeView.Location = new System.Drawing.Point(0, 0);
            this.httpTransactionTreeView.Name = "httpTransactionTreeView";
            treeNode1.Name = "Node0";
            treeNode1.Text = "Web browsing tree view is only available in NetworkMiner Professional";
            this.httpTransactionTreeView.Nodes.AddRange(new System.Windows.Forms.TreeNode[] {
            treeNode1});
            this.httpTransactionTreeView.Size = new System.Drawing.Size(395, 290);
            this.httpTransactionTreeView.TabIndex = 0;
            this.httpTransactionTreeView.AfterSelect += new System.Windows.Forms.TreeViewEventHandler(this.httpTransactionTreeView_AfterSelect);
            this.httpTransactionTreeView.KeyDown += new System.Windows.Forms.KeyEventHandler(this.httpTransactionTreeView_KeyDown);
            // 
            // httpTransactionPropertyGrid
            // 
            this.httpTransactionPropertyGrid.Dock = System.Windows.Forms.DockStyle.Fill;
            this.httpTransactionPropertyGrid.LineColor = System.Drawing.SystemColors.ControlDark;
            this.httpTransactionPropertyGrid.Location = new System.Drawing.Point(0, 0);
            this.httpTransactionPropertyGrid.Name = "httpTransactionPropertyGrid";
            this.httpTransactionPropertyGrid.Size = new System.Drawing.Size(151, 290);
            this.httpTransactionPropertyGrid.TabIndex = 3;
            this.httpTransactionPropertyGrid.ToolbarVisible = false;
            // 
            // panel4
            // 
            this.panel4.Controls.Add(this.findHttpTransactionTextBox);
            this.panel4.Controls.Add(this.findHttpTransactionCaseSensitiveCheckBox);
            this.panel4.Controls.Add(this.findHttpTransactionButton);
            this.panel4.Controls.Add(this.findHttpTransactionLabel);
            this.panel4.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel4.Location = new System.Drawing.Point(3, 3);
            this.panel4.Name = "panel4";
            this.panel4.Size = new System.Drawing.Size(550, 22);
            this.panel4.TabIndex = 1;
            // 
            // findHttpTransactionTextBox
            // 
            this.findHttpTransactionTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.findHttpTransactionTextBox.Location = new System.Drawing.Point(30, 0);
            this.findHttpTransactionTextBox.Name = "findHttpTransactionTextBox";
            this.findHttpTransactionTextBox.Size = new System.Drawing.Size(346, 20);
            this.findHttpTransactionTextBox.TabIndex = 3;
            this.findHttpTransactionTextBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.findHttpTransactionTextBox_KeyDown);
            // 
            // findHttpTransactionCaseSensitiveCheckBox
            // 
            this.findHttpTransactionCaseSensitiveCheckBox.AutoSize = true;
            this.findHttpTransactionCaseSensitiveCheckBox.Dock = System.Windows.Forms.DockStyle.Right;
            this.findHttpTransactionCaseSensitiveCheckBox.Location = new System.Drawing.Point(376, 0);
            this.findHttpTransactionCaseSensitiveCheckBox.Name = "findHttpTransactionCaseSensitiveCheckBox";
            this.findHttpTransactionCaseSensitiveCheckBox.Padding = new System.Windows.Forms.Padding(3, 0, 0, 0);
            this.findHttpTransactionCaseSensitiveCheckBox.Size = new System.Drawing.Size(99, 22);
            this.findHttpTransactionCaseSensitiveCheckBox.TabIndex = 1;
            this.findHttpTransactionCaseSensitiveCheckBox.Text = "Case Sensitive";
            this.findHttpTransactionCaseSensitiveCheckBox.UseVisualStyleBackColor = true;
            // 
            // findHttpTransactionButton
            // 
            this.findHttpTransactionButton.Dock = System.Windows.Forms.DockStyle.Right;
            this.findHttpTransactionButton.Location = new System.Drawing.Point(475, 0);
            this.findHttpTransactionButton.Name = "findHttpTransactionButton";
            this.findHttpTransactionButton.Size = new System.Drawing.Size(75, 22);
            this.findHttpTransactionButton.TabIndex = 2;
            this.findHttpTransactionButton.Text = "Find";
            this.findHttpTransactionButton.UseVisualStyleBackColor = true;
            this.findHttpTransactionButton.Click += new System.EventHandler(this.findHttpTransactionButton_Click);
            // 
            // findHttpTransactionLabel
            // 
            this.findHttpTransactionLabel.AutoSize = true;
            this.findHttpTransactionLabel.Dock = System.Windows.Forms.DockStyle.Left;
            this.findHttpTransactionLabel.Location = new System.Drawing.Point(0, 0);
            this.findHttpTransactionLabel.Name = "findHttpTransactionLabel";
            this.findHttpTransactionLabel.Size = new System.Drawing.Size(30, 13);
            this.findHttpTransactionLabel.TabIndex = 0;
            this.findHttpTransactionLabel.Text = "Find:";
            // 
            // tabPageFiles
            // 
            this.tabPageFiles.Controls.Add(this.filesListView);
            this.tabPageFiles.Controls.Add(this.filesKeywordFilterControl);
            this.tabPageFiles.Location = new System.Drawing.Point(4, 40);
            this.tabPageFiles.Name = "tabPageFiles";
            this.tabPageFiles.Padding = new System.Windows.Forms.Padding(0, 3, 0, 0);
            this.tabPageFiles.Size = new System.Drawing.Size(556, 318);
            this.tabPageFiles.TabIndex = 5;
            this.tabPageFiles.Text = "Files";
            this.tabPageFiles.UseVisualStyleBackColor = true;
            // 
            // filesListView
            // 
            this.filesListView.Activation = System.Windows.Forms.ItemActivation.OneClick;
            this.filesListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.reconstructedFileInitialFrameNumber,
            this.filenameHeader,
            this.extensionHeader,
            this.fileSizeHeader,
            this.sourceHostHeader,
            this.sourcePortHeader,
            this.destinationHostHeader,
            this.destinationPortHeader,
            this.protocolHeader,
            this.reconstructedFileTimestampColumnHeader,
            this.reconstructedFilePathHeader,
            this.detailsHeader});
            this.filesListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.filesListView.FullRowSelect = true;
            this.filesListView.HideSelection = false;
            this.filesListView.Location = new System.Drawing.Point(0, 25);
            this.filesListView.MultiSelect = false;
            this.filesListView.Name = "filesListView";
            this.filesListView.ShowItemToolTips = true;
            this.filesListView.Size = new System.Drawing.Size(556, 293);
            this.filesListView.TabIndex = 1;
            this.filesListView.UseCompatibleStateImageBehavior = false;
            this.filesListView.View = System.Windows.Forms.View.Details;
            this.filesListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            this.filesListView.MouseDown += new System.Windows.Forms.MouseEventHandler(this.filesListView_MouseDown);
            // 
            // reconstructedFileInitialFrameNumber
            // 
            this.reconstructedFileInitialFrameNumber.Text = "Frame nr.";
            // 
            // filenameHeader
            // 
            this.filenameHeader.Text = "Filename";
            // 
            // extensionHeader
            // 
            this.extensionHeader.Text = "Extension";
            // 
            // fileSizeHeader
            // 
            this.fileSizeHeader.Text = "Size";
            this.fileSizeHeader.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            // 
            // sourceHostHeader
            // 
            this.sourceHostHeader.Text = "Source host";
            // 
            // sourcePortHeader
            // 
            this.sourcePortHeader.Text = "S. port";
            // 
            // destinationHostHeader
            // 
            this.destinationHostHeader.Text = "Destination host";
            // 
            // destinationPortHeader
            // 
            this.destinationPortHeader.Text = "D. port";
            // 
            // protocolHeader
            // 
            this.protocolHeader.Text = "Protocol";
            // 
            // reconstructedFileTimestampColumnHeader
            // 
            this.reconstructedFileTimestampColumnHeader.Text = "Timestamp";
            // 
            // reconstructedFilePathHeader
            // 
            this.reconstructedFilePathHeader.Text = "Reconstructed file path";
            // 
            // detailsHeader
            // 
            this.detailsHeader.Text = "Details";
            // 
            // filesKeywordFilterControl
            // 
            this.filesKeywordFilterControl.Dock = System.Windows.Forms.DockStyle.Top;
            this.filesKeywordFilterControl.Location = new System.Drawing.Point(0, 3);
            this.filesKeywordFilterControl.Name = "filesKeywordFilterControl";
            this.filesKeywordFilterControl.Size = new System.Drawing.Size(556, 22);
            this.filesKeywordFilterControl.TabIndex = 0;
            // 
            // tabPageImages
            // 
            this.tabPageImages.Controls.Add(this.imagesListView);
            this.tabPageImages.Location = new System.Drawing.Point(4, 40);
            this.tabPageImages.Name = "tabPageImages";
            this.tabPageImages.Size = new System.Drawing.Size(556, 318);
            this.tabPageImages.TabIndex = 6;
            this.tabPageImages.Text = "Images";
            this.tabPageImages.UseVisualStyleBackColor = true;
            // 
            // imagesListView
            // 
            this.imagesListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.imagesListView.Location = new System.Drawing.Point(0, 0);
            this.imagesListView.Name = "imagesListView";
            this.imagesListView.ShowItemToolTips = true;
            this.imagesListView.Size = new System.Drawing.Size(556, 318);
            this.imagesListView.TabIndex = 0;
            this.imagesListView.UseCompatibleStateImageBehavior = false;
            this.imagesListView.MouseDoubleClick += new System.Windows.Forms.MouseEventHandler(this.imagesListView_MouseDoubleClick);
            this.imagesListView.MouseDown += new System.Windows.Forms.MouseEventHandler(this.imagesListView_MouseDown);
            this.imagesListView.MouseMove += new System.Windows.Forms.MouseEventHandler(this.imagesListView_MouseMove);
            // 
            // tabPageMessages
            // 
            this.tabPageMessages.Controls.Add(this.messagesSplitContainer);
            this.tabPageMessages.Location = new System.Drawing.Point(4, 40);
            this.tabPageMessages.Name = "tabPageMessages";
            this.tabPageMessages.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageMessages.Size = new System.Drawing.Size(556, 318);
            this.tabPageMessages.TabIndex = 12;
            this.tabPageMessages.Text = "Messages";
            this.tabPageMessages.UseVisualStyleBackColor = true;
            // 
            // messagesSplitContainer
            // 
            this.messagesSplitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messagesSplitContainer.Location = new System.Drawing.Point(3, 3);
            this.messagesSplitContainer.Name = "messagesSplitContainer";
            // 
            // messagesSplitContainer.Panel1
            // 
            this.messagesSplitContainer.Panel1.Controls.Add(this.messagesListView);
            this.messagesSplitContainer.Panel1.Controls.Add(this.messagesKeywordFilterControl);
            // 
            // messagesSplitContainer.Panel2
            // 
            this.messagesSplitContainer.Panel2.Controls.Add(this.splitContainer3);
            this.messagesSplitContainer.Size = new System.Drawing.Size(550, 312);
            this.messagesSplitContainer.SplitterDistance = 422;
            this.messagesSplitContainer.TabIndex = 2;
            // 
            // messagesListView
            // 
            this.messagesListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.messageFrameColumnHeader,
            this.messageSourceHostColumnHeader,
            this.messageDestinationHostColumnHeader,
            this.messageFromColumnHeader,
            this.messageToColumnHeader,
            this.messageSubjectColumnHeader,
            this.messageProtocolColumnHeader,
            this.messageTimestampColumnHeader});
            this.messagesListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messagesListView.FullRowSelect = true;
            this.messagesListView.Location = new System.Drawing.Point(0, 22);
            this.messagesListView.MultiSelect = false;
            this.messagesListView.Name = "messagesListView";
            this.messagesListView.ShowItemToolTips = true;
            this.messagesListView.Size = new System.Drawing.Size(422, 290);
            this.messagesListView.TabIndex = 0;
            this.messagesListView.UseCompatibleStateImageBehavior = false;
            this.messagesListView.View = System.Windows.Forms.View.Details;
            this.messagesListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            this.messagesListView.ItemSelectionChanged += new System.Windows.Forms.ListViewItemSelectionChangedEventHandler(this.messagesListView_ItemSelectionChanged);
            // 
            // messageFrameColumnHeader
            // 
            this.messageFrameColumnHeader.Text = "Frame nr.";
            // 
            // messageSourceHostColumnHeader
            // 
            this.messageSourceHostColumnHeader.Text = "Source host";
            // 
            // messageDestinationHostColumnHeader
            // 
            this.messageDestinationHostColumnHeader.Text = "Destination host";
            // 
            // messageFromColumnHeader
            // 
            this.messageFromColumnHeader.Text = "From";
            // 
            // messageToColumnHeader
            // 
            this.messageToColumnHeader.Text = "To";
            // 
            // messageSubjectColumnHeader
            // 
            this.messageSubjectColumnHeader.Text = "Subject";
            this.messageSubjectColumnHeader.Width = 120;
            // 
            // messageProtocolColumnHeader
            // 
            this.messageProtocolColumnHeader.Text = "Protocol";
            // 
            // messageTimestampColumnHeader
            // 
            this.messageTimestampColumnHeader.Text = "Timestamp";
            // 
            // messagesKeywordFilterControl
            // 
            this.messagesKeywordFilterControl.Dock = System.Windows.Forms.DockStyle.Top;
            this.messagesKeywordFilterControl.Location = new System.Drawing.Point(0, 0);
            this.messagesKeywordFilterControl.Name = "messagesKeywordFilterControl";
            this.messagesKeywordFilterControl.Size = new System.Drawing.Size(422, 22);
            this.messagesKeywordFilterControl.TabIndex = 1;
            // 
            // splitContainer3
            // 
            this.splitContainer3.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer3.Location = new System.Drawing.Point(0, 0);
            this.splitContainer3.Name = "splitContainer3";
            this.splitContainer3.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer3.Panel1
            // 
            this.splitContainer3.Panel1.Controls.Add(this.messageAttributeListView);
            // 
            // splitContainer3.Panel2
            // 
            this.splitContainer3.Panel2.Controls.Add(this.splitContainer4);
            this.splitContainer3.Panel2.Controls.Add(this.messageEncodingComboBox);
            this.splitContainer3.Size = new System.Drawing.Size(124, 312);
            this.splitContainer3.SplitterDistance = 71;
            this.splitContainer3.SplitterWidth = 2;
            this.splitContainer3.TabIndex = 2;
            // 
            // messageAttributeListView
            // 
            this.messageAttributeListView.BackColor = System.Drawing.SystemColors.Control;
            this.messageAttributeListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.attributeNameColumnHeader,
            this.attributeValueColumnHeader});
            this.messageAttributeListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messageAttributeListView.FullRowSelect = true;
            this.messageAttributeListView.HeaderStyle = System.Windows.Forms.ColumnHeaderStyle.Nonclickable;
            this.messageAttributeListView.Location = new System.Drawing.Point(0, 0);
            this.messageAttributeListView.Name = "messageAttributeListView";
            this.messageAttributeListView.ShowItemToolTips = true;
            this.messageAttributeListView.Size = new System.Drawing.Size(124, 71);
            this.messageAttributeListView.TabIndex = 0;
            this.messageAttributeListView.UseCompatibleStateImageBehavior = false;
            this.messageAttributeListView.View = System.Windows.Forms.View.Details;
            // 
            // attributeNameColumnHeader
            // 
            this.attributeNameColumnHeader.Text = "Attribute";
            this.attributeNameColumnHeader.Width = 100;
            // 
            // attributeValueColumnHeader
            // 
            this.attributeValueColumnHeader.Text = "Value";
            this.attributeValueColumnHeader.Width = 300;
            // 
            // splitContainer4
            // 
            this.splitContainer4.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer4.Location = new System.Drawing.Point(0, 21);
            this.splitContainer4.Name = "splitContainer4";
            this.splitContainer4.Orientation = System.Windows.Forms.Orientation.Horizontal;
            // 
            // splitContainer4.Panel1
            // 
            this.splitContainer4.Panel1.Controls.Add(this.messageTextBox);
            // 
            // splitContainer4.Panel2
            // 
            this.splitContainer4.Panel2.Controls.Add(this.messageAttachmentListView);
            this.splitContainer4.Size = new System.Drawing.Size(124, 218);
            this.splitContainer4.SplitterDistance = 147;
            this.splitContainer4.SplitterWidth = 2;
            this.splitContainer4.TabIndex = 3;
            // 
            // messageTextBox
            // 
            this.messageTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messageTextBox.Location = new System.Drawing.Point(0, 0);
            this.messageTextBox.Multiline = true;
            this.messageTextBox.Name = "messageTextBox";
            this.messageTextBox.ReadOnly = true;
            this.messageTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.messageTextBox.Size = new System.Drawing.Size(124, 147);
            this.messageTextBox.TabIndex = 0;
            // 
            // messageAttachmentListView
            // 
            this.messageAttachmentListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeader1,
            this.columnHeader2});
            this.messageAttachmentListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.messageAttachmentListView.FullRowSelect = true;
            this.messageAttachmentListView.Location = new System.Drawing.Point(0, 0);
            this.messageAttachmentListView.MultiSelect = false;
            this.messageAttachmentListView.Name = "messageAttachmentListView";
            this.messageAttachmentListView.ShowItemToolTips = true;
            this.messageAttachmentListView.Size = new System.Drawing.Size(124, 69);
            this.messageAttachmentListView.TabIndex = 2;
            this.messageAttachmentListView.UseCompatibleStateImageBehavior = false;
            this.messageAttachmentListView.View = System.Windows.Forms.View.Details;
            this.messageAttachmentListView.MouseDown += new System.Windows.Forms.MouseEventHandler(this.messageAttachmentListView_MouseDown);
            // 
            // columnHeader1
            // 
            this.columnHeader1.Text = "Attachement";
            this.columnHeader1.Width = 150;
            // 
            // columnHeader2
            // 
            this.columnHeader2.Text = "Size";
            this.columnHeader2.TextAlign = System.Windows.Forms.HorizontalAlignment.Right;
            this.columnHeader2.Width = 100;
            // 
            // messageEncodingComboBox
            // 
            this.messageEncodingComboBox.Dock = System.Windows.Forms.DockStyle.Top;
            this.messageEncodingComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.messageEncodingComboBox.FormattingEnabled = true;
            this.messageEncodingComboBox.Location = new System.Drawing.Point(0, 0);
            this.messageEncodingComboBox.Name = "messageEncodingComboBox";
            this.messageEncodingComboBox.Size = new System.Drawing.Size(124, 21);
            this.messageEncodingComboBox.TabIndex = 1;
            this.messageEncodingComboBox.SelectedIndexChanged += new System.EventHandler(this.messageEncodingComboBox_SelectedIndexChanged);
            // 
            // tabPageCredentials
            // 
            this.tabPageCredentials.Controls.Add(this.credentialsListView);
            this.tabPageCredentials.Controls.Add(this.panel3);
            this.tabPageCredentials.Location = new System.Drawing.Point(4, 40);
            this.tabPageCredentials.Name = "tabPageCredentials";
            this.tabPageCredentials.Size = new System.Drawing.Size(556, 318);
            this.tabPageCredentials.TabIndex = 7;
            this.tabPageCredentials.Text = "Credentials";
            this.tabPageCredentials.UseVisualStyleBackColor = true;
            // 
            // credentialsListView
            // 
            this.credentialsListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.loggedInClientHeader,
            this.serverHostHeader,
            this.protocolStringHeader,
            this.usernameHeader,
            this.passwordHeader,
            this.validHeader,
            this.loginTimestamp});
            this.credentialsListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.credentialsListView.FullRowSelect = true;
            this.credentialsListView.HideSelection = false;
            this.credentialsListView.Location = new System.Drawing.Point(0, 23);
            this.credentialsListView.Name = "credentialsListView";
            this.credentialsListView.ShowItemToolTips = true;
            this.credentialsListView.Size = new System.Drawing.Size(556, 295);
            this.credentialsListView.TabIndex = 0;
            this.credentialsListView.UseCompatibleStateImageBehavior = false;
            this.credentialsListView.View = System.Windows.Forms.View.Details;
            this.credentialsListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            // 
            // loggedInClientHeader
            // 
            this.loggedInClientHeader.Text = "Client";
            // 
            // serverHostHeader
            // 
            this.serverHostHeader.Text = "Server";
            // 
            // protocolStringHeader
            // 
            this.protocolStringHeader.Text = "Protocol";
            // 
            // usernameHeader
            // 
            this.usernameHeader.Text = "Username";
            // 
            // passwordHeader
            // 
            this.passwordHeader.Text = "Password";
            // 
            // validHeader
            // 
            this.validHeader.Text = "Valid login";
            // 
            // loginTimestamp
            // 
            this.loginTimestamp.Text = "Login timestamp";
            // 
            // panel3
            // 
            this.panel3.Controls.Add(this.showCookiesCheckBox);
            this.panel3.Controls.Add(this.maskPasswordsCheckBox);
            this.panel3.Controls.Add(this.showNtlmSspCheckBox);
            this.panel3.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel3.Location = new System.Drawing.Point(0, 0);
            this.panel3.Name = "panel3";
            this.panel3.Size = new System.Drawing.Size(556, 23);
            this.panel3.TabIndex = 4;
            // 
            // showCookiesCheckBox
            // 
            this.showCookiesCheckBox.AutoSize = true;
            this.showCookiesCheckBox.Checked = true;
            this.showCookiesCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.showCookiesCheckBox.Location = new System.Drawing.Point(3, 3);
            this.showCookiesCheckBox.Name = "showCookiesCheckBox";
            this.showCookiesCheckBox.Size = new System.Drawing.Size(94, 17);
            this.showCookiesCheckBox.TabIndex = 1;
            this.showCookiesCheckBox.Text = "Show Cookies";
            this.showCookiesCheckBox.UseVisualStyleBackColor = true;
            this.showCookiesCheckBox.CheckedChanged += new System.EventHandler(this.credentialsSettingsCheckBox_Click);
            // 
            // maskPasswordsCheckBox
            // 
            this.maskPasswordsCheckBox.AutoSize = true;
            this.maskPasswordsCheckBox.Location = new System.Drawing.Point(290, 3);
            this.maskPasswordsCheckBox.Name = "maskPasswordsCheckBox";
            this.maskPasswordsCheckBox.Size = new System.Drawing.Size(106, 17);
            this.maskPasswordsCheckBox.TabIndex = 3;
            this.maskPasswordsCheckBox.Text = "Mask Passwords";
            this.maskPasswordsCheckBox.UseVisualStyleBackColor = true;
            this.maskPasswordsCheckBox.CheckedChanged += new System.EventHandler(this.credentialsSettingsCheckBox_Click);
            // 
            // showNtlmSspCheckBox
            // 
            this.showNtlmSspCheckBox.AutoSize = true;
            this.showNtlmSspCheckBox.Checked = true;
            this.showNtlmSspCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.showNtlmSspCheckBox.Location = new System.Drawing.Point(103, 3);
            this.showNtlmSspCheckBox.Name = "showNtlmSspCheckBox";
            this.showNtlmSspCheckBox.Size = new System.Drawing.Size(181, 17);
            this.showNtlmSspCheckBox.TabIndex = 2;
            this.showNtlmSspCheckBox.Text = "Show NTLM challenge-response";
            this.showNtlmSspCheckBox.UseVisualStyleBackColor = true;
            this.showNtlmSspCheckBox.CheckedChanged += new System.EventHandler(this.credentialsSettingsCheckBox_Click);
            // 
            // tabPageSessions
            // 
            this.tabPageSessions.Controls.Add(this.sessionsListView);
            this.tabPageSessions.Controls.Add(this.sessionsKeywordFilterControl);
            this.tabPageSessions.Location = new System.Drawing.Point(4, 40);
            this.tabPageSessions.Name = "tabPageSessions";
            this.tabPageSessions.Size = new System.Drawing.Size(556, 318);
            this.tabPageSessions.TabIndex = 11;
            this.tabPageSessions.Text = "Sessions";
            this.tabPageSessions.UseVisualStyleBackColor = true;
            // 
            // sessionsListView
            // 
            this.sessionsListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.sessionFrameNrColumnHeader,
            this.sessionClientHostColumnHeader,
            this.sessionClientPortColumnHeader,
            this.sessionServerHostColumnHeader,
            this.sessionServerPortColumnHeader,
            this.sessionProtocolColumnHeader,
            this.sessionStartTimeColumnHeader});
            this.sessionsListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.sessionsListView.FullRowSelect = true;
            this.sessionsListView.Location = new System.Drawing.Point(0, 22);
            this.sessionsListView.MultiSelect = false;
            this.sessionsListView.Name = "sessionsListView";
            this.sessionsListView.Size = new System.Drawing.Size(556, 296);
            this.sessionsListView.TabIndex = 0;
            this.sessionsListView.UseCompatibleStateImageBehavior = false;
            this.sessionsListView.View = System.Windows.Forms.View.Details;
            this.sessionsListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            // 
            // sessionFrameNrColumnHeader
            // 
            this.sessionFrameNrColumnHeader.Text = "Frame nr.";
            // 
            // sessionClientHostColumnHeader
            // 
            this.sessionClientHostColumnHeader.Text = "Client host";
            // 
            // sessionClientPortColumnHeader
            // 
            this.sessionClientPortColumnHeader.Text = "C. port";
            // 
            // sessionServerHostColumnHeader
            // 
            this.sessionServerHostColumnHeader.Text = "Server host";
            // 
            // sessionServerPortColumnHeader
            // 
            this.sessionServerPortColumnHeader.Text = "S. port";
            // 
            // sessionProtocolColumnHeader
            // 
            this.sessionProtocolColumnHeader.Text = "Protocol (application layer)";
            // 
            // sessionStartTimeColumnHeader
            // 
            this.sessionStartTimeColumnHeader.Text = "Start time";
            // 
            // sessionsKeywordFilterControl
            // 
            this.sessionsKeywordFilterControl.Dock = System.Windows.Forms.DockStyle.Top;
            this.sessionsKeywordFilterControl.Location = new System.Drawing.Point(0, 0);
            this.sessionsKeywordFilterControl.Name = "sessionsKeywordFilterControl";
            this.sessionsKeywordFilterControl.Size = new System.Drawing.Size(556, 22);
            this.sessionsKeywordFilterControl.TabIndex = 1;
            // 
            // tabPageDns
            // 
            this.tabPageDns.Controls.Add(this.dnsListView);
            this.tabPageDns.Controls.Add(this.dnsKeywordFilterControl);
            this.tabPageDns.Location = new System.Drawing.Point(4, 40);
            this.tabPageDns.Name = "tabPageDns";
            this.tabPageDns.Padding = new System.Windows.Forms.Padding(0, 3, 0, 0);
            this.tabPageDns.Size = new System.Drawing.Size(556, 318);
            this.tabPageDns.TabIndex = 10;
            this.tabPageDns.Text = "DNS";
            this.tabPageDns.UseVisualStyleBackColor = true;
            // 
            // dnsListView
            // 
            this.dnsListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeaderDnsFrameNumber,
            this.columnHeaderDnsTimestamp,
            this.columnHeaderDnsClient,
            this.columnHeaderDnsClientPort,
            this.columnHeaderDnsServer,
            this.columnHeaderDnsServerPort,
            this.columnHeaderDnsIpTtl,
            this.columnHeaderDnsDnsTtl,
            this.columnHeaderDnsTransactionId,
            this.columnHeaderDnsRecordType,
            this.columnHeaderDnsQuery,
            this.columnHeaderDnsAnswer,
            this.columnHeaderAlexaTop1M});
            this.dnsListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dnsListView.FullRowSelect = true;
            this.dnsListView.HideSelection = false;
            this.dnsListView.Location = new System.Drawing.Point(0, 25);
            this.dnsListView.Name = "dnsListView";
            this.dnsListView.ShowItemToolTips = true;
            this.dnsListView.Size = new System.Drawing.Size(556, 293);
            this.dnsListView.TabIndex = 0;
            this.dnsListView.UseCompatibleStateImageBehavior = false;
            this.dnsListView.View = System.Windows.Forms.View.Details;
            this.dnsListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            // 
            // columnHeaderDnsFrameNumber
            // 
            this.columnHeaderDnsFrameNumber.Text = "Frame nr.";
            this.columnHeaderDnsFrameNumber.Width = 50;
            // 
            // columnHeaderDnsTimestamp
            // 
            this.columnHeaderDnsTimestamp.Text = "Timestamp";
            this.columnHeaderDnsTimestamp.Width = 50;
            // 
            // columnHeaderDnsClient
            // 
            this.columnHeaderDnsClient.Text = "Client";
            this.columnHeaderDnsClient.Width = 50;
            // 
            // columnHeaderDnsClientPort
            // 
            this.columnHeaderDnsClientPort.Text = "Client Port";
            this.columnHeaderDnsClientPort.Width = 50;
            // 
            // columnHeaderDnsServer
            // 
            this.columnHeaderDnsServer.Text = "Server";
            this.columnHeaderDnsServer.Width = 50;
            // 
            // columnHeaderDnsServerPort
            // 
            this.columnHeaderDnsServerPort.Text = "Server Port";
            this.columnHeaderDnsServerPort.Width = 50;
            // 
            // columnHeaderDnsIpTtl
            // 
            this.columnHeaderDnsIpTtl.Text = "IP TTL";
            this.columnHeaderDnsIpTtl.Width = 50;
            // 
            // columnHeaderDnsDnsTtl
            // 
            this.columnHeaderDnsDnsTtl.Text = "DNS TTL (time)";
            this.columnHeaderDnsDnsTtl.Width = 50;
            // 
            // columnHeaderDnsTransactionId
            // 
            this.columnHeaderDnsTransactionId.Text = "Transaction ID";
            this.columnHeaderDnsTransactionId.Width = 50;
            // 
            // columnHeaderDnsRecordType
            // 
            this.columnHeaderDnsRecordType.Text = "Type";
            this.columnHeaderDnsRecordType.Width = 50;
            // 
            // columnHeaderDnsQuery
            // 
            this.columnHeaderDnsQuery.Text = "DNS Query";
            this.columnHeaderDnsQuery.Width = 50;
            // 
            // columnHeaderDnsAnswer
            // 
            this.columnHeaderDnsAnswer.Text = "DNS Answer";
            this.columnHeaderDnsAnswer.Width = 50;
            // 
            // columnHeaderAlexaTop1M
            // 
            this.columnHeaderAlexaTop1M.Text = "Alexa Top 1M";
            // 
            // dnsKeywordFilterControl
            // 
            this.dnsKeywordFilterControl.Dock = System.Windows.Forms.DockStyle.Top;
            this.dnsKeywordFilterControl.Location = new System.Drawing.Point(0, 3);
            this.dnsKeywordFilterControl.Name = "dnsKeywordFilterControl";
            this.dnsKeywordFilterControl.Size = new System.Drawing.Size(556, 22);
            this.dnsKeywordFilterControl.TabIndex = 1;
            // 
            // tabPageParameters
            // 
            this.tabPageParameters.Controls.Add(this.parametersListView);
            this.tabPageParameters.Controls.Add(this.parametersKeywordFilterControl);
            this.tabPageParameters.ForeColor = System.Drawing.SystemColors.MenuHighlight;
            this.tabPageParameters.Location = new System.Drawing.Point(4, 40);
            this.tabPageParameters.Name = "tabPageParameters";
            this.tabPageParameters.Padding = new System.Windows.Forms.Padding(0, 3, 0, 0);
            this.tabPageParameters.Size = new System.Drawing.Size(556, 318);
            this.tabPageParameters.TabIndex = 9;
            this.tabPageParameters.Text = "Parameters";
            this.tabPageParameters.UseVisualStyleBackColor = true;
            // 
            // parametersListView
            // 
            this.parametersListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.parameterName,
            this.parameterValue,
            this.parameterFrameNumber,
            this.parameterSourceHost,
            this.parameterSourcePort,
            this.parameterDestinationHost,
            this.parameterDestinationPort,
            this.parameterTimestamp,
            this.parameterDetails});
            this.parametersListView.ContextMenuStrip = this.parametersContextMenuStrip;
            this.parametersListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.parametersListView.FullRowSelect = true;
            this.parametersListView.Location = new System.Drawing.Point(0, 25);
            this.parametersListView.Name = "parametersListView";
            this.parametersListView.Size = new System.Drawing.Size(556, 293);
            this.parametersListView.TabIndex = 0;
            this.parametersListView.UseCompatibleStateImageBehavior = false;
            this.parametersListView.View = System.Windows.Forms.View.Details;
            this.parametersListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            // 
            // parameterName
            // 
            this.parameterName.Text = "Parameter name";
            // 
            // parameterValue
            // 
            this.parameterValue.Text = "Parameter value";
            // 
            // parameterFrameNumber
            // 
            this.parameterFrameNumber.Text = "Frame number";
            // 
            // parameterSourceHost
            // 
            this.parameterSourceHost.Text = "Source host";
            // 
            // parameterSourcePort
            // 
            this.parameterSourcePort.Text = "Source port";
            // 
            // parameterDestinationHost
            // 
            this.parameterDestinationHost.Text = "Destination host";
            // 
            // parameterDestinationPort
            // 
            this.parameterDestinationPort.Text = "Destination port";
            // 
            // parameterTimestamp
            // 
            this.parameterTimestamp.Text = "Timestamp";
            // 
            // parameterDetails
            // 
            this.parameterDetails.Text = "Details";
            // 
            // parametersKeywordFilterControl
            // 
            this.parametersKeywordFilterControl.Dock = System.Windows.Forms.DockStyle.Top;
            this.parametersKeywordFilterControl.ForeColor = System.Drawing.SystemColors.ControlText;
            this.parametersKeywordFilterControl.Location = new System.Drawing.Point(0, 3);
            this.parametersKeywordFilterControl.Name = "parametersKeywordFilterControl";
            this.parametersKeywordFilterControl.Size = new System.Drawing.Size(556, 22);
            this.parametersKeywordFilterControl.TabIndex = 1;
            // 
            // tabPageKeywords
            // 
            this.tabPageKeywords.Controls.Add(this.splitContainer2);
            this.tabPageKeywords.Controls.Add(this.removeKeywordButton);
            this.tabPageKeywords.Location = new System.Drawing.Point(4, 40);
            this.tabPageKeywords.Name = "tabPageKeywords";
            this.tabPageKeywords.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageKeywords.Size = new System.Drawing.Size(556, 318);
            this.tabPageKeywords.TabIndex = 8;
            this.tabPageKeywords.Text = "Keywords";
            this.tabPageKeywords.UseVisualStyleBackColor = true;
            // 
            // splitContainer2
            // 
            this.splitContainer2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer2.Location = new System.Drawing.Point(3, 3);
            this.splitContainer2.Name = "splitContainer2";
            // 
            // splitContainer2.Panel1
            // 
            this.splitContainer2.Panel1.Controls.Add(this.keywordListBox);
            this.splitContainer2.Panel1.Controls.Add(this.label1);
            this.splitContainer2.Panel1.Controls.Add(this.addKeywordsFromFileButton);
            this.splitContainer2.Panel1.Controls.Add(this.addKeywordButton);
            this.splitContainer2.Panel1.Controls.Add(this.keywordTextBox);
            // 
            // splitContainer2.Panel2
            // 
            this.splitContainer2.Panel2.Controls.Add(this.detectedKeywordsListView);
            this.splitContainer2.Size = new System.Drawing.Size(550, 312);
            this.splitContainer2.SplitterDistance = 179;
            this.splitContainer2.TabIndex = 9;
            // 
            // keywordListBox
            // 
            this.keywordListBox.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.keywordListBox.FormattingEnabled = true;
            this.keywordListBox.Location = new System.Drawing.Point(3, 93);
            this.keywordListBox.Name = "keywordListBox";
            this.keywordListBox.SelectionMode = System.Windows.Forms.SelectionMode.MultiExtended;
            this.keywordListBox.Size = new System.Drawing.Size(173, 277);
            this.keywordListBox.TabIndex = 6;
            this.keywordListBox.ControlAdded += new System.Windows.Forms.ControlEventHandler(this.keywordListBox_ControlAdded);
            this.keywordListBox.ControlRemoved += new System.Windows.Forms.ControlEventHandler(this.keywordListBox_ControlRemoved);
            // 
            // label1
            // 
            this.label1.Location = new System.Drawing.Point(3, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(176, 29);
            this.label1.TabIndex = 7;
            this.label1.Text = "Enter keyword as string like \"foo\" or in hex format like \"0x626172\"";
            // 
            // addKeywordsFromFileButton
            // 
            this.addKeywordsFromFileButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.addKeywordsFromFileButton.Image = global::NetworkMiner.Properties.Resources.openHS;
            this.addKeywordsFromFileButton.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.addKeywordsFromFileButton.Location = new System.Drawing.Point(3, 61);
            this.addKeywordsFromFileButton.Name = "addKeywordsFromFileButton";
            this.addKeywordsFromFileButton.Size = new System.Drawing.Size(173, 26);
            this.addKeywordsFromFileButton.TabIndex = 8;
            this.addKeywordsFromFileButton.Text = "Add keywords from text file  ";
            this.addKeywordsFromFileButton.TextImageRelation = System.Windows.Forms.TextImageRelation.ImageBeforeText;
            this.addKeywordsFromFileButton.UseVisualStyleBackColor = true;
            this.addKeywordsFromFileButton.Click += new System.EventHandler(this.addKeywordsFromFileButton_Click);
            // 
            // addKeywordButton
            // 
            this.addKeywordButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.addKeywordButton.Location = new System.Drawing.Point(142, 30);
            this.addKeywordButton.Name = "addKeywordButton";
            this.addKeywordButton.Size = new System.Drawing.Size(34, 23);
            this.addKeywordButton.TabIndex = 5;
            this.addKeywordButton.Text = "Add";
            this.addKeywordButton.UseVisualStyleBackColor = true;
            this.addKeywordButton.Click += new System.EventHandler(this.addKeyword);
            // 
            // keywordTextBox
            // 
            this.keywordTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.keywordTextBox.Location = new System.Drawing.Point(2, 32);
            this.keywordTextBox.Name = "keywordTextBox";
            this.keywordTextBox.Size = new System.Drawing.Size(134, 20);
            this.keywordTextBox.TabIndex = 1;
            this.keywordTextBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.keywordTextBox_KeyDown);
            // 
            // detectedKeywordsListView
            // 
            this.detectedKeywordsListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.columnHeaderFrameNr,
            this.columnHeaderTimestamp,
            this.columnHeaderKeyword,
            this.columnHeaderContext,
            this.columnHeaderSourceHost,
            this.columnHeaderSourcePort,
            this.columnDestinationHost,
            this.columnHeaderDestinationPort});
            this.detectedKeywordsListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.detectedKeywordsListView.FullRowSelect = true;
            this.detectedKeywordsListView.Location = new System.Drawing.Point(0, 0);
            this.detectedKeywordsListView.Name = "detectedKeywordsListView";
            this.detectedKeywordsListView.Size = new System.Drawing.Size(367, 312);
            this.detectedKeywordsListView.TabIndex = 2;
            this.detectedKeywordsListView.UseCompatibleStateImageBehavior = false;
            this.detectedKeywordsListView.View = System.Windows.Forms.View.Details;
            this.detectedKeywordsListView.ColumnClick += new System.Windows.Forms.ColumnClickEventHandler(this.ListViewColumnClick);
            // 
            // columnHeaderFrameNr
            // 
            this.columnHeaderFrameNr.Text = "Frame number";
            this.columnHeaderFrameNr.Width = 50;
            // 
            // columnHeaderTimestamp
            // 
            this.columnHeaderTimestamp.Text = "Timestamp";
            this.columnHeaderTimestamp.Width = 50;
            // 
            // columnHeaderKeyword
            // 
            this.columnHeaderKeyword.Text = "Keyword";
            this.columnHeaderKeyword.Width = 50;
            // 
            // columnHeaderContext
            // 
            this.columnHeaderContext.Text = "Context";
            this.columnHeaderContext.Width = 50;
            // 
            // columnHeaderSourceHost
            // 
            this.columnHeaderSourceHost.Text = "Source Host";
            this.columnHeaderSourceHost.Width = 50;
            // 
            // columnHeaderSourcePort
            // 
            this.columnHeaderSourcePort.Text = "Source Port";
            this.columnHeaderSourcePort.Width = 50;
            // 
            // columnDestinationHost
            // 
            this.columnDestinationHost.Text = "Destination Host";
            this.columnDestinationHost.Width = 50;
            // 
            // columnHeaderDestinationPort
            // 
            this.columnHeaderDestinationPort.Text = "Destination Port";
            this.columnHeaderDestinationPort.Width = 50;
            // 
            // removeKeywordButton
            // 
            this.removeKeywordButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.removeKeywordButton.Location = new System.Drawing.Point(104, -2873);
            this.removeKeywordButton.Name = "removeKeywordButton";
            this.removeKeywordButton.Size = new System.Drawing.Size(75, 23);
            this.removeKeywordButton.TabIndex = 4;
            this.removeKeywordButton.Text = "Remove";
            this.removeKeywordButton.UseVisualStyleBackColor = true;
            this.removeKeywordButton.Click += new System.EventHandler(this.removeKeywordButton_Click);
            // 
            // tabPageCleartext
            // 
            this.tabPageCleartext.Controls.Add(this.cleartextTextBox);
            this.tabPageCleartext.Controls.Add(this.panel1);
            this.tabPageCleartext.Controls.Add(this.button1);
            this.tabPageCleartext.Location = new System.Drawing.Point(4, 40);
            this.tabPageCleartext.Name = "tabPageCleartext";
            this.tabPageCleartext.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageCleartext.Size = new System.Drawing.Size(556, 318);
            this.tabPageCleartext.TabIndex = 3;
            this.tabPageCleartext.Text = "Cleartext";
            this.tabPageCleartext.UseVisualStyleBackColor = true;
            // 
            // cleartextTextBox
            // 
            this.cleartextTextBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cleartextTextBox.ForeColor = System.Drawing.SystemColors.WindowText;
            this.cleartextTextBox.Location = new System.Drawing.Point(3, 58);
            this.cleartextTextBox.Multiline = true;
            this.cleartextTextBox.Name = "cleartextTextBox";
            this.cleartextTextBox.ReadOnly = true;
            this.cleartextTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.cleartextTextBox.Size = new System.Drawing.Size(550, 234);
            this.cleartextTextBox.TabIndex = 0;
            // 
            // panel1
            // 
            this.panel1.Controls.Add(this.changeCleartextDictionaryButton);
            this.panel1.Controls.Add(this.label2);
            this.panel1.Controls.Add(this.cleartextSearchModeComboBox);
            this.panel1.Controls.Add(this.dictionaryNameLabel);
            this.panel1.Controls.Add(this.label5);
            this.panel1.Dock = System.Windows.Forms.DockStyle.Top;
            this.panel1.Location = new System.Drawing.Point(3, 3);
            this.panel1.Name = "panel1";
            this.panel1.Size = new System.Drawing.Size(550, 55);
            this.panel1.TabIndex = 3;
            // 
            // changeCleartextDictionaryButton
            // 
            this.changeCleartextDictionaryButton.Image = global::NetworkMiner.Properties.Resources.openHS;
            this.changeCleartextDictionaryButton.ImageAlign = System.Drawing.ContentAlignment.MiddleLeft;
            this.changeCleartextDictionaryButton.Location = new System.Drawing.Point(149, 1);
            this.changeCleartextDictionaryButton.Margin = new System.Windows.Forms.Padding(0);
            this.changeCleartextDictionaryButton.Name = "changeCleartextDictionaryButton";
            this.changeCleartextDictionaryButton.Size = new System.Drawing.Size(121, 23);
            this.changeCleartextDictionaryButton.TabIndex = 7;
            this.changeCleartextDictionaryButton.Text = "Change dictionary";
            this.changeCleartextDictionaryButton.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.changeCleartextDictionaryButton.UseVisualStyleBackColor = true;
            this.changeCleartextDictionaryButton.Click += new System.EventHandler(this.changeCleartextDictionaryButton_Click_1);
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(3, 30);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(86, 13);
            this.label2.TabIndex = 6;
            this.label2.Text = "Cleartext search:";
            // 
            // cleartextSearchModeComboBox
            // 
            this.cleartextSearchModeComboBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.cleartextSearchModeComboBox.FormattingEnabled = true;
            this.cleartextSearchModeComboBox.Items.AddRange(new object[] {
            "Complete - Search full packet data in all packets",
            "Application layer - Search payload of TCP and UDP packets",
            "Non-parsed - Only search in non-parsed protocols",
            "Disabled - Disable cleartext search"});
            this.cleartextSearchModeComboBox.Location = new System.Drawing.Point(95, 27);
            this.cleartextSearchModeComboBox.Name = "cleartextSearchModeComboBox";
            this.cleartextSearchModeComboBox.Size = new System.Drawing.Size(450, 21);
            this.cleartextSearchModeComboBox.TabIndex = 5;
            this.cleartextSearchModeComboBox.SelectedIndexChanged += new System.EventHandler(this.cleartextSearchModeComboBox_SelectedIndexChanged);
            // 
            // dictionaryNameLabel
            // 
            this.dictionaryNameLabel.AutoSize = true;
            this.dictionaryNameLabel.Location = new System.Drawing.Point(103, 6);
            this.dictionaryNameLabel.Name = "dictionaryNameLabel";
            this.dictionaryNameLabel.Size = new System.Drawing.Size(31, 13);
            this.dictionaryNameLabel.TabIndex = 4;
            this.dictionaryNameLabel.Text = "none";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(3, 6);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(94, 13);
            this.label5.TabIndex = 3;
            this.label5.Text = "Loaded dictionary:";
            // 
            // button1
            // 
            this.button1.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.button1.Location = new System.Drawing.Point(3, 292);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(550, 23);
            this.button1.TabIndex = 2;
            this.button1.Text = "Clear";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click_1);
            // 
            // tabPageReceivedFrames
            // 
            this.tabPageReceivedFrames.Controls.Add(this.framesTreeView);
            this.tabPageReceivedFrames.Controls.Add(this.ReceivedFramesClearButton);
            this.tabPageReceivedFrames.Location = new System.Drawing.Point(4, 40);
            this.tabPageReceivedFrames.Name = "tabPageReceivedFrames";
            this.tabPageReceivedFrames.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageReceivedFrames.Size = new System.Drawing.Size(556, 318);
            this.tabPageReceivedFrames.TabIndex = 1;
            this.tabPageReceivedFrames.Text = "Frames";
            this.tabPageReceivedFrames.UseVisualStyleBackColor = true;
            // 
            // framesTreeView
            // 
            this.framesTreeView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.framesTreeView.Location = new System.Drawing.Point(3, 3);
            this.framesTreeView.Name = "framesTreeView";
            this.framesTreeView.Size = new System.Drawing.Size(550, 289);
            this.framesTreeView.TabIndex = 0;
            // 
            // ReceivedFramesClearButton
            // 
            this.ReceivedFramesClearButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.ReceivedFramesClearButton.Location = new System.Drawing.Point(3, 292);
            this.ReceivedFramesClearButton.Name = "ReceivedFramesClearButton";
            this.ReceivedFramesClearButton.Size = new System.Drawing.Size(550, 23);
            this.ReceivedFramesClearButton.TabIndex = 1;
            this.ReceivedFramesClearButton.Text = "Clear";
            this.ReceivedFramesClearButton.UseVisualStyleBackColor = true;
            this.ReceivedFramesClearButton.Click += new System.EventHandler(this.button1_Click);
            // 
            // tabPageAnomalyLog
            // 
            this.tabPageAnomalyLog.Controls.Add(this.anomalyLog);
            this.tabPageAnomalyLog.Controls.Add(this.clearAnomaliesButton);
            this.tabPageAnomalyLog.Location = new System.Drawing.Point(4, 40);
            this.tabPageAnomalyLog.Name = "tabPageAnomalyLog";
            this.tabPageAnomalyLog.Padding = new System.Windows.Forms.Padding(3);
            this.tabPageAnomalyLog.Size = new System.Drawing.Size(556, 318);
            this.tabPageAnomalyLog.TabIndex = 0;
            this.tabPageAnomalyLog.Text = "Anomalies";
            this.tabPageAnomalyLog.UseVisualStyleBackColor = true;
            // 
            // anomalyLog
            // 
            this.anomalyLog.AcceptsReturn = true;
            this.anomalyLog.AcceptsTab = true;
            this.anomalyLog.Dock = System.Windows.Forms.DockStyle.Fill;
            this.anomalyLog.Font = new System.Drawing.Font("Courier New", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.anomalyLog.Location = new System.Drawing.Point(3, 3);
            this.anomalyLog.Multiline = true;
            this.anomalyLog.Name = "anomalyLog";
            this.anomalyLog.ReadOnly = true;
            this.anomalyLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.anomalyLog.Size = new System.Drawing.Size(550, 289);
            this.anomalyLog.TabIndex = 7;
            // 
            // clearAnomaliesButton
            // 
            this.clearAnomaliesButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.clearAnomaliesButton.Location = new System.Drawing.Point(3, 292);
            this.clearAnomaliesButton.Name = "clearAnomaliesButton";
            this.clearAnomaliesButton.Size = new System.Drawing.Size(550, 23);
            this.clearAnomaliesButton.TabIndex = 8;
            this.clearAnomaliesButton.Text = "Clear";
            this.clearAnomaliesButton.UseVisualStyleBackColor = true;
            this.clearAnomaliesButton.Click += new System.EventHandler(this.clearAnomaliesButton_Click);
            // 
            // casePanelBox
            // 
            this.casePanelBox.Controls.Add(this.casePanelFileListView);
            this.casePanelBox.Controls.Add(this.reloadCaseFilesButton);
            this.casePanelBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.casePanelBox.Location = new System.Drawing.Point(0, 0);
            this.casePanelBox.Name = "casePanelBox";
            this.casePanelBox.Size = new System.Drawing.Size(116, 368);
            this.casePanelBox.TabIndex = 9;
            this.casePanelBox.TabStop = false;
            this.casePanelBox.Text = "Case Panel";
            // 
            // casePanelFileListView
            // 
            this.casePanelFileListView.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.caseFilenameColumn,
            this.caseMd5Column});
            this.casePanelFileListView.ContextMenuStrip = this.caseFileContextMenuStrip;
            this.casePanelFileListView.Dock = System.Windows.Forms.DockStyle.Fill;
            this.casePanelFileListView.FullRowSelect = true;
            this.casePanelFileListView.Location = new System.Drawing.Point(3, 16);
            this.casePanelFileListView.Name = "casePanelFileListView";
            this.casePanelFileListView.ShowItemToolTips = true;
            this.casePanelFileListView.Size = new System.Drawing.Size(110, 326);
            this.casePanelFileListView.TabIndex = 0;
            this.casePanelFileListView.UseCompatibleStateImageBehavior = false;
            this.casePanelFileListView.View = System.Windows.Forms.View.Details;
            // 
            // caseFilenameColumn
            // 
            this.caseFilenameColumn.Text = "Filename";
            // 
            // caseMd5Column
            // 
            this.caseMd5Column.Text = "MD5";
            // 
            // reloadCaseFilesButton
            // 
            this.reloadCaseFilesButton.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.reloadCaseFilesButton.Location = new System.Drawing.Point(3, 342);
            this.reloadCaseFilesButton.Name = "reloadCaseFilesButton";
            this.reloadCaseFilesButton.Size = new System.Drawing.Size(110, 23);
            this.reloadCaseFilesButton.TabIndex = 1;
            this.reloadCaseFilesButton.Text = "Reload Case Files";
            this.reloadCaseFilesButton.UseVisualStyleBackColor = true;
            this.reloadCaseFilesButton.Click += new System.EventHandler(this.reloadCaseFilesButton_Click);
            // 
            // NetworkMinerForm
            // 
            this.AllowDrop = true;
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(690, 447);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.button2);
            this.Controls.Add(this.networkAdaptersComboBox);
            this.Controls.Add(this.stopButton);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.menuStrip1);
            this.Controls.Add(this.startButton);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.MainMenuStrip = this.menuStrip1;
            this.Name = "NetworkMinerForm";
            this.Text = "NetworkMiner 2.2";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.NetworkMinerForm_FormClosing);
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.NetworkMinerForm_FormClosed);
            this.DragDrop += new System.Windows.Forms.DragEventHandler(this.NetworkMinerForm_DragDrop);
            this.DragEnter += new System.Windows.Forms.DragEventHandler(this.NetworkMinerForm_DragEnter);
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.menuStrip1.ResumeLayout(false);
            this.menuStrip1.PerformLayout();
            this.hostMenuStrip.ResumeLayout(false);
            this.parametersContextMenuStrip.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.dataSet1)).EndInit();
            this.caseFileContextMenuStrip.ResumeLayout(false);
            this.browsersMenuStrip.ResumeLayout(false);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.tabControl.ResumeLayout(false);
            this.tabPageDetectedHosts.ResumeLayout(false);
            this.panel2.ResumeLayout(false);
            this.panel2.PerformLayout();
            this.tabPageBrowsers.ResumeLayout(false);
            this.browsersSplitContainer.Panel1.ResumeLayout(false);
            this.browsersSplitContainer.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.browsersSplitContainer)).EndInit();
            this.browsersSplitContainer.ResumeLayout(false);
            this.panel4.ResumeLayout(false);
            this.panel4.PerformLayout();
            this.tabPageFiles.ResumeLayout(false);
            this.tabPageImages.ResumeLayout(false);
            this.tabPageMessages.ResumeLayout(false);
            this.messagesSplitContainer.Panel1.ResumeLayout(false);
            this.messagesSplitContainer.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.messagesSplitContainer)).EndInit();
            this.messagesSplitContainer.ResumeLayout(false);
            this.splitContainer3.Panel1.ResumeLayout(false);
            this.splitContainer3.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer3)).EndInit();
            this.splitContainer3.ResumeLayout(false);
            this.splitContainer4.Panel1.ResumeLayout(false);
            this.splitContainer4.Panel1.PerformLayout();
            this.splitContainer4.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer4)).EndInit();
            this.splitContainer4.ResumeLayout(false);
            this.tabPageCredentials.ResumeLayout(false);
            this.panel3.ResumeLayout(false);
            this.panel3.PerformLayout();
            this.tabPageSessions.ResumeLayout(false);
            this.tabPageDns.ResumeLayout(false);
            this.tabPageParameters.ResumeLayout(false);
            this.tabPageKeywords.ResumeLayout(false);
            this.splitContainer2.Panel1.ResumeLayout(false);
            this.splitContainer2.Panel1.PerformLayout();
            this.splitContainer2.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer2)).EndInit();
            this.splitContainer2.ResumeLayout(false);
            this.tabPageCleartext.ResumeLayout(false);
            this.tabPageCleartext.PerformLayout();
            this.panel1.ResumeLayout(false);
            this.panel1.PerformLayout();
            this.tabPageReceivedFrames.ResumeLayout(false);
            this.tabPageAnomalyLog.ResumeLayout(false);
            this.tabPageAnomalyLog.PerformLayout();
            this.casePanelBox.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }
        #endregion

        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.MenuStrip menuStrip1;
        private System.Windows.Forms.Button startButton;
        private System.Windows.Forms.Button stopButton;
        private System.Windows.Forms.TabControl tabControl;
        private System.Windows.Forms.TabPage tabPageAnomalyLog;
        private System.Windows.Forms.TabPage tabPageReceivedFrames;
        private System.Windows.Forms.TreeView framesTreeView;
        private System.Windows.Forms.ComboBox networkAdaptersComboBox;
        private System.Windows.Forms.TreeView networkHostTreeView;
        private System.Windows.Forms.TabPage tabPageCleartext;
        private System.Windows.Forms.TextBox cleartextTextBox;
        //private CleartextTextBox cleartextTextBox;
        private System.Windows.Forms.Button ReceivedFramesClearButton;
        private System.Windows.Forms.ToolStripMenuItem fileToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem toolsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem exitToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem helpToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem aboutNetworkMinerToolStripMenuItem;
        //private CrystalDecisions.Windows.Forms.CrystalReportViewer crystalReportViewer1;
        private System.Windows.Forms.Panel panel1;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label dictionaryNameLabel;
        private System.Windows.Forms.Button detectedHostsTreeRebuildButton;
        private System.Windows.Forms.TextBox anomalyLog;
        private System.Windows.Forms.Button clearAnomaliesButton;
        private System.Data.DataSet dataSet1;
        private System.Windows.Forms.ToolStripMenuItem openToolStripMenuItem;
        private System.Windows.Forms.OpenFileDialog openPcapFileDialog;
        private System.Windows.Forms.ToolStripMenuItem resetCapturedDataToolStripMenuItem;
        private System.Windows.Forms.TabPage tabPageFiles;
        private System.Windows.Forms.TabPage tabPageImages;
        private System.Windows.Forms.ListView filesListView;
        private System.Windows.Forms.ColumnHeader filenameHeader;
        private System.Windows.Forms.ColumnHeader detailsHeader;
        private System.Windows.Forms.ColumnHeader sourceHostHeader;
        private System.Windows.Forms.ColumnHeader sourcePortHeader;
        private System.Windows.Forms.ColumnHeader destinationHostHeader;
        private System.Windows.Forms.ColumnHeader destinationPortHeader;
        private System.Windows.Forms.ColumnHeader fileSizeHeader;
        private System.Windows.Forms.ColumnHeader reconstructedFilePathHeader;
        private System.Windows.Forms.ListView imagesListView;
        private System.Windows.Forms.ColumnHeader protocolHeader;
        private System.Windows.Forms.TabPage tabPageCredentials;
        private System.Windows.Forms.ListView credentialsListView;
        private System.Windows.Forms.ColumnHeader serverHostHeader;
        private System.Windows.Forms.ColumnHeader protocolStringHeader;
        private System.Windows.Forms.ColumnHeader usernameHeader;
        private System.Windows.Forms.ColumnHeader passwordHeader;
        private System.Windows.Forms.ColumnHeader validHeader;
        private System.Windows.Forms.TabPage tabPageKeywords;
        private System.Windows.Forms.ListView detectedKeywordsListView;
        private System.Windows.Forms.ColumnHeader columnHeaderFrameNr;
        private System.Windows.Forms.ColumnHeader columnHeaderKeyword;
        private System.Windows.Forms.ColumnHeader columnHeaderContext;
        private System.Windows.Forms.Button addKeywordButton;
        private System.Windows.Forms.Button removeKeywordButton;
        private System.Windows.Forms.ColumnHeader columnHeaderTimestamp;
        private System.Windows.Forms.ColumnHeader columnHeaderSourceHost;
        private System.Windows.Forms.ColumnHeader columnHeaderSourcePort;
        private System.Windows.Forms.ColumnHeader columnDestinationHost;
        private System.Windows.Forms.ColumnHeader columnHeaderDestinationPort;
        private System.Windows.Forms.ListBox keywordListBox;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox keywordTextBox;
        private System.Windows.Forms.ComboBox cleartextSearchModeComboBox;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TabPage tabPageParameters;
        private System.Windows.Forms.ListView parametersListView;
        private System.Windows.Forms.ColumnHeader parameterSourceHost;
        private System.Windows.Forms.ColumnHeader parameterDestinationHost;
        private System.Windows.Forms.ColumnHeader parameterSourcePort;
        private System.Windows.Forms.ColumnHeader parameterDestinationPort;
        private System.Windows.Forms.ColumnHeader parameterName;
        private System.Windows.Forms.ColumnHeader parameterValue;
        private System.Windows.Forms.ColumnHeader parameterTimestamp;
        private System.Windows.Forms.ColumnHeader parameterDetails;
        private System.Windows.Forms.ColumnHeader parameterFrameNumber;
        private System.Windows.Forms.ColumnHeader loggedInClientHeader;
        private System.Windows.Forms.ColumnHeader loginTimestamp;
        private System.Windows.Forms.ToolStripMenuItem startCapturingToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem stopCapturingToolStripMenuItem;
        private System.Windows.Forms.Button button2;
        private System.Windows.Forms.TabPage tabPageDns;
        private System.Windows.Forms.ListView dnsListView;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsFrameNumber;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsTimestamp;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsClient;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsServer;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsQuery;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsAnswer;
        private System.Windows.Forms.ToolStripStatusLabel toolStripStatusLabel1;
        private System.Windows.Forms.ToolStripProgressBar snifferBufferToolStripProgressBar;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsIpTtl;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsRecordType;
        private System.Windows.Forms.ComboBox hostSortOrderComboBox;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsTransactionId;
        private System.Windows.Forms.Panel panel2;
        private System.Windows.Forms.Label hostSortingLabel;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsDnsTtl;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsClientPort;
        private System.Windows.Forms.ColumnHeader columnHeaderDnsServerPort;
        private System.Windows.Forms.GroupBox casePanelBox;
        private System.Windows.Forms.ListView casePanelFileListView;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.Button reloadCaseFilesButton;
        private System.Windows.Forms.ContextMenuStrip caseFileContextMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem removeCaseFileMenuItem;
        private System.Windows.Forms.ColumnHeader reconstructedFileInitialFrameNumber;
        private System.Windows.Forms.ColumnHeader reconstructedFileTimestampColumnHeader;
        private System.Windows.Forms.ColumnHeader caseFilenameColumn;
        private System.Windows.Forms.ColumnHeader caseMd5Column;
        private System.Windows.Forms.ToolStripMenuItem openParentFolderToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem printReportToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip hostMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem selectHostColorMenuItem;
        private System.Windows.Forms.ColorDialog colorDialog1;
        private System.Windows.Forms.ToolStripMenuItem removeHostColorToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip parametersContextMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem copyParameterNameToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyParameterValueToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyTextToolStripMenuItem;
        private System.Windows.Forms.TabPage tabPageSessions;
        private System.Windows.Forms.ListView sessionsListView;
        private System.Windows.Forms.ColumnHeader sessionFrameNrColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionClientHostColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionClientPortColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionServerHostColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionServerPortColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionProtocolColumnHeader;
        private System.Windows.Forms.ColumnHeader sessionStartTimeColumnHeader;
        private System.Windows.Forms.TabPage tabPageMessages;
        private System.Windows.Forms.SplitContainer messagesSplitContainer;
        private System.Windows.Forms.ListView messagesListView;
        private System.Windows.Forms.SplitContainer splitContainer3;
        private System.Windows.Forms.TextBox messageTextBox;
        private System.Windows.Forms.ColumnHeader messageFrameColumnHeader;
        private System.Windows.Forms.ColumnHeader messageSourceHostColumnHeader;
        private System.Windows.Forms.ColumnHeader messageDestinationHostColumnHeader;
        private System.Windows.Forms.ColumnHeader messageFromColumnHeader;
        private System.Windows.Forms.ColumnHeader messageToColumnHeader;
        private System.Windows.Forms.ColumnHeader messageSubjectColumnHeader;
        private System.Windows.Forms.ColumnHeader messageProtocolColumnHeader;
        private System.Windows.Forms.ColumnHeader messageTimestampColumnHeader;
        private System.Windows.Forms.ListView messageAttributeListView;
        private System.Windows.Forms.ColumnHeader attributeNameColumnHeader;
        private System.Windows.Forms.ColumnHeader attributeValueColumnHeader;
        private System.Windows.Forms.ColumnHeader extensionHeader;
        private System.Windows.Forms.ToolStripMenuItem exportToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem credentialsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem dnsRecordsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem fileInfosToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem hostsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem messagesToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem parametersToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem sessionsToolStripMenuItem;
        private System.Windows.Forms.SaveFileDialog exportDataToFileDialog;
        private System.Windows.Forms.ToolStripMenuItem settingsToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem receivePcapOverIPToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem getUpgradeCodeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem signWithLicenseToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.Button changeCleartextDictionaryButton;
        private System.Windows.Forms.OpenFileDialog openTextFileDialog;
        private System.Windows.Forms.ToolStripMenuItem downloadRIPEDBToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator2;
        private System.Windows.Forms.CheckBox showCookiesCheckBox;
        private System.Windows.Forms.CheckBox showNtlmSspCheckBox;
        private System.Windows.Forms.CheckBox maskPasswordsCheckBox;
        private System.Windows.Forms.ToolStripMenuItem clearGUIToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator3;
        private System.Windows.Forms.ColumnHeader columnHeaderAlexaTop1M;
        private System.Windows.Forms.Button addKeywordsFromFileButton;
        private System.Windows.Forms.ToolStripMenuItem showMetadataToolStripMenuItem;
        private System.Windows.Forms.ComboBox messageEncodingComboBox;
        private KeywordFilterControlForListViewItems parametersKeywordFilterControl;
        private KeywordFilterControlForListViewItems filesKeywordFilterControl;
        private KeywordFilterControlForListViewItems dnsKeywordFilterControl;
        private System.Windows.Forms.TabPage tabPageBrowsers;
        private System.Windows.Forms.TreeView httpTransactionTreeView;
        private System.Windows.Forms.ToolStripMenuItem removeSelectedFilesAndReloadCaseFilesToolStripMenuItem;
        private System.Windows.Forms.Panel panel3;
        public System.Windows.Forms.TabPage tabPageDetectedHosts;
        private KeywordFilterControlForListViewItems messagesKeywordFilterControl;
        private System.Windows.Forms.ListView messageAttachmentListView;
        private System.Windows.Forms.ColumnHeader columnHeader1;
        private System.Windows.Forms.ColumnHeader columnHeader2;
        private System.Windows.Forms.SplitContainer splitContainer4;
        private KeywordFilterControlForListViewItems sessionsKeywordFilterControl;
        private System.Windows.Forms.ToolStripMenuItem readFromPacketCacheToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem expandAllToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem collapseAllToolStripMenuItem;
        private System.Windows.Forms.ContextMenuStrip browsersMenuStrip;
        private System.Windows.Forms.ToolStripMenuItem expandAllToolStripMenuItem1;
        private System.Windows.Forms.ToolStripMenuItem collapseAllToolStripMenuItem1;
        private System.Windows.Forms.PropertyGrid httpTransactionPropertyGrid;
        private System.Windows.Forms.SplitContainer browsersSplitContainer;
        private System.Windows.Forms.ToolStripMenuItem setAdvertismentColorToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator4;
        private System.Windows.Forms.Panel panel4;
        private System.Windows.Forms.TextBox findHttpTransactionTextBox;
        private System.Windows.Forms.Button findHttpTransactionButton;
        private System.Windows.Forms.CheckBox findHttpTransactionCaseSensitiveCheckBox;
        private System.Windows.Forms.Label findHttpTransactionLabel;
        private System.Windows.Forms.ToolStripMenuItem setInternetTrackerColorToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem findNextToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem selectParentNodeToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem collapseAllButThisToolStripMenuItem;
        private System.Windows.Forms.SplitContainer splitContainer2;
        private System.Windows.Forms.ToolStripMenuItem checkForUpdatesToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator5;
    }
}

