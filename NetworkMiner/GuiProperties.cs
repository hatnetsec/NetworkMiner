using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Reflection;

using System.Xml.Serialization;


namespace NetworkMiner {

    [Obfuscation(Feature = "internalization", Exclude = true)]
    public class GuiProperties {

        public event PropertyChangedEventHandler PropertyChanged;

        private bool automaticallyResizeColumnsWhenParsingComplete = true;
        private ushort columnAutoResizeMaxWidth = 300;
        private int maxDisplayedFrames = 1000;

        private bool useHostsTab = true;
        private bool useBrowsersTab = true;
        private bool useFilesTab = true;
        private bool useImagesTab = true;
        private bool useMessagesTab = true;
        private bool useCredentialsTab = true;
        private bool useSessionsTab = true;
        private bool useDnsTab = true;
        private bool useParametersTab = true;
        private bool useKeywordsTab = true;
        private bool useCleartextTab = false;
        private bool useFramesTab = false;
        private bool useAnomaliesTab = true;

        private bool preserveLinesInCsvExport = true;
        //private bool showPartialDownloads = false;
        private TimeZoneInfo timestampDisplayTimeZone = TimeZoneInfo.Local;//Change to UTC

        private System.Drawing.Color advertismentColor, internetTrackerColor;


        public GuiProperties() {
            this.advertismentColor = System.Drawing.Color.Red;
            this.internetTrackerColor = System.Drawing.Color.Blue;
        }

        public GuiProperties Clone() {
            System.Xml.Serialization.XmlSerializer serializer = new System.Xml.Serialization.XmlSerializer(this.GetType());
            using (System.IO.MemoryStream stream = new System.IO.MemoryStream()) {
                serializer.Serialize(stream, this);
                stream.Seek(0, System.IO.SeekOrigin.Begin);
                return serializer.Deserialize(stream) as GuiProperties;
            }
        }

        public bool AutomaticallyResizeColumnsWhenParsingComplete {
            get {
                return automaticallyResizeColumnsWhenParsingComplete;
            }
            set {
                automaticallyResizeColumnsWhenParsingComplete = value;
            }
        }

        [DescriptionAttribute("Maximum width of columns when doing auto-resize to fit content. 0 = Unlimited (always fit content).")]
        public ushort ColumnAutoResizeMaxWidth {
            get { return this.columnAutoResizeMaxWidth; }
            set { this.columnAutoResizeMaxWidth = value; }
        }

        [DescriptionAttribute("-1 = No limit\n0 = Don't show any frames\n1000 = Default limitation")]
        public int MaxDisplayedFrames {
            get { return this.maxDisplayedFrames; }
            set {
                if (value < 0)
                    this.maxDisplayedFrames = -1;
                else
                    this.maxDisplayedFrames = value;
            }
        }


        [XmlIgnore]
        public System.Drawing.Color AdvertismentColor
        {
            get { return this.advertismentColor; }
            set { this.advertismentColor = value; }
        }
        [Browsable(false)]
        public string AdvertismentColorHtml
        {
            get { return System.Drawing.ColorTranslator.ToHtml(this.AdvertismentColor); }
            set { this.AdvertismentColor = System.Drawing.ColorTranslator.FromHtml(value); }
        }

        [XmlIgnore]
        public System.Drawing.Color InternetTrackerColor
        {
            get { return this.internetTrackerColor; }
            set { this.internetTrackerColor = value; }
        }
        [Browsable(false)]
        public string InternetTrackerColorHtml
        {
            get { return System.Drawing.ColorTranslator.ToHtml(this.InternetTrackerColor); }
            set { this.InternetTrackerColor = System.Drawing.ColorTranslator.FromHtml(value); }
        }

        public bool UseHostsTab {
            get { return this.useHostsTab; }
            set { this.useHostsTab = value; }
        }
        public bool UseBrowsersTab {
            get {
                return this.useBrowsersTab;
            }
            set { this.useBrowsersTab = value; }
        }
        public bool UseFilesTab {
            get {
                return this.useFilesTab;
            }
            set { this.useFilesTab = value; }
        }
        public bool UseImagesTab {
            get {
                return this.useImagesTab;
            }
            set { this.useImagesTab = value; }
        }
        public bool UseMessagesTab {
            get {
                return this.useMessagesTab;
            }
            set { this.useMessagesTab = value; }
        }
        public bool UseCredentialsTab {
            get {
                return this.useCredentialsTab;
            }
            set { this.useCredentialsTab = value; }
        }
        public bool UseSessionsTab {
            get {
                return this.useSessionsTab;
            }
            set { this.useSessionsTab = value; }
        }
        public bool UseDnsTab {
            get {
                return this.useDnsTab;
            }
            set { this.useDnsTab = value; }
        }
        public bool UseParametersTab {
            get {
                return this.useParametersTab;
            }
            set { this.useParametersTab = value; }
        }
        public bool UseKeywordsTab {
            get {
                return this.useKeywordsTab;
            }
            set { this.useKeywordsTab = value; }
        }
        public bool UseCleartextTab {
            get {
                return this.useCleartextTab;
            }
            set { this.useCleartextTab = value; }
        }
        public bool UseFramesTab {
            get {
                return this.useFramesTab;
            }
            set { this.useFramesTab = value; }
        }
        public bool UseAnomaliesTab {
            get {
                return this.useAnomaliesTab;
            }
            set { this.useAnomaliesTab = value; }
        }

        public bool? CheckForUpdatesOnStartup { get; set; } = null;


        [DescriptionAttribute("If newline characters in strings should be preserved when exporting to a CSV file.")]
        public bool PreserveLinesInCsvExport {
            get {
                return preserveLinesInCsvExport;
            }

            set {
                preserveLinesInCsvExport = value;
            }
        }

        [XmlIgnore]
        [DescriptionAttribute("Time zone to use for displaying all timestamp values.")]
        public TimeZoneInfo TimeZone {
            get { return this.timestampDisplayTimeZone; }
            set { this.timestampDisplayTimeZone = value; }
        }
        [XmlIgnore]
        [DescriptionAttribute("Time zone offset (hh:mm:ss) from UTC to use for displaying all timestamp values.")]
        public TimeSpan TimeZoneOffset {
            get { return this.timestampDisplayTimeZone.BaseUtcOffset; }
            set {
                this.TimestampDisplayTimeZone = TimeZoneInfo.CreateCustomTimeZone(value.ToString(), value, value.ToString(), value.ToString()).ToSerializedString();
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("TimeZoneOffset"));
            }
        }
        [XmlIgnore]
        [DescriptionAttribute("Time Zone")]
        public DateTimeKind TimeZoneSelection {
            get {
                if (this.timestampDisplayTimeZone == TimeZoneInfo.Local)
                    return DateTimeKind.Local;
                else if (this.timestampDisplayTimeZone == TimeZoneInfo.Utc)
                    return DateTimeKind.Utc;
                else
                    return DateTimeKind.Unspecified;
            }
            set {
                if (value == DateTimeKind.Local)
                    this.timestampDisplayTimeZone = TimeZoneInfo.Local;
                else if (value == DateTimeKind.Utc)
                    this.timestampDisplayTimeZone = TimeZoneInfo.Utc;
                PropertyChanged?.Invoke(this, new PropertyChangedEventArgs("TimeZoneOffset"));
            }
        }

        [Browsable(false)]
        public string TimestampDisplayTimeZone {
            get { return this.timestampDisplayTimeZone.ToSerializedString(); }
            set {
                TimeZoneInfo customTimeZone = TimeZoneInfo.FromSerializedString(value);
                if(TimeZoneInfo.Local.BaseUtcOffset == customTimeZone.BaseUtcOffset) {
                    this.timestampDisplayTimeZone = TimeZoneInfo.Local;
                    return;
                }
                else if(TimeZoneInfo.Utc.BaseUtcOffset == customTimeZone.BaseUtcOffset) {
                    this.timestampDisplayTimeZone = TimeZoneInfo.Utc;
                    return;
                }
                foreach (TimeZoneInfo tzi in TimeZoneInfo.GetSystemTimeZones())
                    if (tzi.BaseUtcOffset == customTimeZone.BaseUtcOffset) {
                        this.timestampDisplayTimeZone = tzi;
                        return;
                    }
                this.timestampDisplayTimeZone = customTimeZone;
            }
        }

        public string ToCustomTimeZoneString(DateTime timestamp) {
            DateTime timeInCustomZone = TimeZoneInfo.ConvertTimeFromUtc(timestamp.ToUniversalTime(), this.timestampDisplayTimeZone);
            //return timeInCustomZone.ToString();

            /**
             * With DateTime values, the "zzz" custom format specifier represents the signed offset of the
             * local operating system's time zone from UTC, measured in hours and minutes.
             * It does not reflect the value of an instance's System.DateTime.Kind property.
             **/
            //return timeInCustomZone.ToString("yyyy-MM-dd HH:mm:ss \"UTC\"zzz");
            //string s = timeInCustomZone.ToString("yyyy'-'MM'-'dd' 'HH':'mm':'ss' UTC'fffffffK");
            //string s = timeInCustomZone.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fffffffK");
            //string s = timeInCustomZone.ToString("o");
            TimeSpan timeZoneOffset = this.timestampDisplayTimeZone.GetUtcOffset(timeInCustomZone);
            StringBuilder s = new StringBuilder(timeInCustomZone.ToString("yyyy-MM-dd HH:mm:ss"));
            if (timeZoneOffset >= TimeSpan.FromSeconds(0))
                s.Append(" UTC+" + timeZoneOffset.ToString("hh"));
            else
                s.Append(" UTC-" + timeZoneOffset.ToString("hh"));

            return s.ToString();
        }

        /*
        [DescriptionAttribute("If partial HTTP downloads (a.k.a. 'Range Requests' or 'Byte Serving') should be displayed. Partial downloads that have been reassembled to complete files are always displayed")]
        public bool ShowPartialDownloads
        {
            get
            {
                return this.showPartialDownloads;
            }
            set
            {
                this.showPartialDownloads = value;
            }
        }*/
        }
    }
