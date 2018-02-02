using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner {
    public partial class CaseFileForm : Form {

        private DataTable table;

        private const string NAME = "Name";
        private const string VALUE = "Value";

        public CaseFileForm(CaseFile caseFile) {
            InitializeComponent();
            this.table = new DataTable();
            this.table.Columns.Add(NAME, typeof(string));
            this.table.Columns.Add(VALUE, typeof(string));
            this.AddRow("Filename", caseFile.Filename);
            this.AddRow("Start", caseFile.FirstFrameTimestamp.ToString());
            this.AddRow("End", caseFile.LastFrameTimestamp.ToString());
            this.AddRow("Frames", caseFile.FramesCount.ToString());
            this.AddRow("MD5", caseFile.Md5);
            this.AddRow("Parsing Time", caseFile.ParsingTime.ToString());

            List<KeyValuePair<string, string>> metadata = caseFile.Metadata;
            lock (metadata) {
                foreach (KeyValuePair<string, string> kvp in metadata)
                    this.AddRow(kvp.Key, kvp.Value);
            }

            this.metadataGridView.DataSource = this.table;
        }

        private void AddRow(string name, string value) {
            DataRow row = this.table.NewRow();
            row[NAME] = name;
            row[VALUE] = value;
            this.table.Rows.Add(row);
        }
    }
}
