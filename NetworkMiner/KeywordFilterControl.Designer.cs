namespace NetworkMiner {
    partial class KeywordFilterControl<T> {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing) {
            if (disposing && (components != null)) {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            this.label1 = new System.Windows.Forms.Label();
            this.keywordComboBox = new System.Windows.Forms.ComboBox();
            this.caseSensitiveCheckBox = new System.Windows.Forms.CheckBox();
            this.clearKeywordButton = new System.Windows.Forms.Button();
            this.applyKeywordButton = new System.Windows.Forms.Button();
            this.filterModeComboBox = new System.Windows.Forms.ComboBox();
            this.columnComboBox = new System.Windows.Forms.ComboBox();
            this.SuspendLayout();
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Dock = System.Windows.Forms.DockStyle.Left;
            this.label1.Location = new System.Drawing.Point(0, 0);
            this.label1.Margin = new System.Windows.Forms.Padding(3);
            this.label1.Name = "label1";
            this.label1.Padding = new System.Windows.Forms.Padding(0, 5, 0, 0);
            this.label1.Size = new System.Drawing.Size(75, 18);
            this.label1.TabIndex = 0;
            this.label1.Text = "Filter keyword:";
            // 
            // keywordComboBox
            // 
            this.keywordComboBox.Dock = System.Windows.Forms.DockStyle.Fill;
            this.keywordComboBox.FormattingEnabled = true;
            this.keywordComboBox.Location = new System.Drawing.Point(75, 0);
            this.keywordComboBox.Name = "keywordComboBox";
            this.keywordComboBox.Size = new System.Drawing.Size(358, 21);
            this.keywordComboBox.TabIndex = 1;
            this.keywordComboBox.TextChanged += new System.EventHandler(this.validateInputSettings);
            this.keywordComboBox.KeyDown += new System.Windows.Forms.KeyEventHandler(this.keywordComboBox_KeyDown);
            // 
            // caseSensitiveCheckBox
            // 
            this.caseSensitiveCheckBox.AutoSize = true;
            this.caseSensitiveCheckBox.Dock = System.Windows.Forms.DockStyle.Right;
            this.caseSensitiveCheckBox.Location = new System.Drawing.Point(433, 0);
            this.caseSensitiveCheckBox.Name = "caseSensitiveCheckBox";
            this.caseSensitiveCheckBox.Padding = new System.Windows.Forms.Padding(3, 0, 0, 0);
            this.caseSensitiveCheckBox.Size = new System.Drawing.Size(97, 22);
            this.caseSensitiveCheckBox.TabIndex = 2;
            this.caseSensitiveCheckBox.Text = "Case sensitive";
            this.caseSensitiveCheckBox.UseVisualStyleBackColor = true;
            this.caseSensitiveCheckBox.CheckedChanged += new System.EventHandler(this.validateInputSettings);
            // 
            // clearKeywordButton
            // 
            this.clearKeywordButton.Dock = System.Windows.Forms.DockStyle.Right;
            this.clearKeywordButton.Location = new System.Drawing.Point(695, 0);
            this.clearKeywordButton.Name = "clearKeywordButton";
            this.clearKeywordButton.Size = new System.Drawing.Size(41, 22);
            this.clearKeywordButton.TabIndex = 3;
            this.clearKeywordButton.Text = "Clear";
            this.clearKeywordButton.UseVisualStyleBackColor = true;
            this.clearKeywordButton.Click += new System.EventHandler(this.clearKeywordButton_Click);
            // 
            // applyKeywordButton
            // 
            this.applyKeywordButton.Dock = System.Windows.Forms.DockStyle.Right;
            this.applyKeywordButton.Location = new System.Drawing.Point(736, 0);
            this.applyKeywordButton.Name = "applyKeywordButton";
            this.applyKeywordButton.Size = new System.Drawing.Size(41, 22);
            this.applyKeywordButton.TabIndex = 4;
            this.applyKeywordButton.Text = "Apply";
            this.applyKeywordButton.UseVisualStyleBackColor = true;
            this.applyKeywordButton.Click += new System.EventHandler(this.applyKeywordButton_Click);
            // 
            // filterModeComboBox
            // 
            this.filterModeComboBox.Dock = System.Windows.Forms.DockStyle.Right;
            this.filterModeComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.filterModeComboBox.FormattingEnabled = true;
            this.filterModeComboBox.Location = new System.Drawing.Point(530, 0);
            this.filterModeComboBox.Name = "filterModeComboBox";
            this.filterModeComboBox.Size = new System.Drawing.Size(87, 21);
            this.filterModeComboBox.TabIndex = 5;
            this.filterModeComboBox.SelectedIndexChanged += new System.EventHandler(this.validateInputSettings);
            // 
            // columnComboBox
            // 
            this.columnComboBox.Dock = System.Windows.Forms.DockStyle.Right;
            this.columnComboBox.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.columnComboBox.FormattingEnabled = true;
            this.columnComboBox.Items.AddRange(new object[] {
            "Any column"});
            this.columnComboBox.Location = new System.Drawing.Point(617, 0);
            this.columnComboBox.Name = "columnComboBox";
            this.columnComboBox.Size = new System.Drawing.Size(78, 21);
            this.columnComboBox.TabIndex = 6;
            // 
            // KeywordFilterControl
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.keywordComboBox);
            this.Controls.Add(this.caseSensitiveCheckBox);
            this.Controls.Add(this.filterModeComboBox);
            this.Controls.Add(this.columnComboBox);
            this.Controls.Add(this.clearKeywordButton);
            this.Controls.Add(this.applyKeywordButton);
            this.Controls.Add(this.label1);
            this.Name = "KeywordFilterControl";
            this.Size = new System.Drawing.Size(777, 22);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox keywordComboBox;
        private System.Windows.Forms.CheckBox caseSensitiveCheckBox;
        private System.Windows.Forms.Button clearKeywordButton;
        private System.Windows.Forms.Button applyKeywordButton;
        private System.Windows.Forms.ComboBox filterModeComboBox;
        private System.Windows.Forms.ComboBox columnComboBox;
    }
}
