using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner {

    
    class KeywordFilterControlForListViewItems : KeywordFilterControl<ListViewItem> {
        //I need to create this wrapper class because of some bug in Visual Studio that prevents the Designer view from showing generic GUI objects
        //http://stackoverflow.com/questions/9314/could-not-find-type-error-loading-a-form-in-the-windows-forms-designer
    }
}
