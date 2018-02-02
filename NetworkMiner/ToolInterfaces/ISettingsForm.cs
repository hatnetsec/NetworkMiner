using System;
using System.Collections.Generic;
using System.Text;

namespace NetworkMiner.ToolInterfaces {
    public interface ISettingsForm : System.Windows.Forms.IContainerControl {

        System.Windows.Forms.DialogResult ShowDialog();
    }
}
