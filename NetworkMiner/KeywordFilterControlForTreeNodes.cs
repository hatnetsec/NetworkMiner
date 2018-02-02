using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;

namespace NetworkMiner {
    class KeywordFilterControlForTreeNodes : KeywordFilterControl<TreeNode> {
        //I need to create this wrapper class because of some bug in Visual Studio that prevents the Designer view from showing generic GUI objects
        //http://stackoverflow.com/questions/9314/could-not-find-type-error-loading-a-form-in-the-windows-forms-designer
        public new void Add(TreeNode item) {
            //base.Add(item);
            this.UnfilteredList.Add(item);
            this.AddItemCallback(item);//don't do any string matching upon add, the node's children might change things later on...
        }

    }

    
}
