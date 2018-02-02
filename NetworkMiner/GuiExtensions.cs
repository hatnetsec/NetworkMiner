using System;
using System.Collections.Generic;
using System.Text;
using System.Windows.Forms;
using System.Reflection;

// you need this once (only), and it must be in this namespace
namespace System.Runtime.CompilerServices {
    [AttributeUsage(AttributeTargets.Assembly | AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class ExtensionAttribute : Attribute { }
}

namespace NetworkMiner {

    public static class GuiExtensions {

        public static void SetDoubleBuffered(this Control control, bool enable) {
            PropertyInfo doubleBufferPropertyInfo = control.GetType().GetProperty("DoubleBuffered", BindingFlags.Instance | BindingFlags.NonPublic);
            doubleBufferPropertyInfo.SetValue(control, enable, null);
        }

        public static IEnumerable<TreeNode> GetOpenChildTreeNodes(this TreeNode treeNode) {
            if (treeNode.IsExpanded)
                foreach (TreeNode n in treeNode.Nodes) {
                    yield return n;
                    if(n.IsExpanded)
                        foreach (TreeNode cn in n.GetOpenChildTreeNodes())//recursion
                            yield return cn;
                }
        }

    }
}
