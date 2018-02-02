namespace NetworkMiner {
    partial class ExtractedFileDetailsForm {
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

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent() {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ExtractedFileDetailsForm));
            this.fileDetailsPropertyGrid = new System.Windows.Forms.PropertyGrid();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.SuspendLayout();
            // 
            // fileDetailsPropertyGrid
            // 
            this.fileDetailsPropertyGrid.CommandsVisibleIfAvailable = false;
            this.fileDetailsPropertyGrid.Dock = System.Windows.Forms.DockStyle.Fill;
            this.fileDetailsPropertyGrid.HelpVisible = false;
            this.fileDetailsPropertyGrid.Location = new System.Drawing.Point(0, 0);
            this.fileDetailsPropertyGrid.Name = "fileDetailsPropertyGrid";
            this.fileDetailsPropertyGrid.PropertySort = System.Windows.Forms.PropertySort.NoSort;
            this.fileDetailsPropertyGrid.Size = new System.Drawing.Size(629, 150);
            this.fileDetailsPropertyGrid.TabIndex = 0;
            this.fileDetailsPropertyGrid.ToolbarVisible = false;
            // 
            // statusStrip1
            // 
            this.statusStrip1.Location = new System.Drawing.Point(0, 150);
            this.statusStrip1.Name = "statusStrip1";
            this.statusStrip1.Size = new System.Drawing.Size(629, 22);
            this.statusStrip1.TabIndex = 1;
            this.statusStrip1.Text = "statusStrip1";
            // 
            // ExtractedFileDetailsForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(629, 172);
            this.Controls.Add(this.fileDetailsPropertyGrid);
            this.Controls.Add(this.statusStrip1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "ExtractedFileDetailsForm";
            this.Text = "File Details";
            this.VisibleChanged += new System.EventHandler(this.FileDetailsForm_VisibleChanged);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.PropertyGrid fileDetailsPropertyGrid;
        private System.Windows.Forms.StatusStrip statusStrip1;
    }
}