using System;
namespace NetworkMiner.ToolInterfaces {
    public interface IColorHandler<TKey> {
        void AddColor(TKey key, System.Drawing.Color color);
        void RemoveColors(bool updateGuiObjects);
        void Clear();
        void Colorize(TKey key, System.Windows.Forms.TreeNode treeNode);
        void Colorize(TKey key, System.Windows.Forms.ListViewItem listViewItem);
        System.Collections.Generic.ICollection<TKey> Keys { get; }
        bool ReloadRequired { get; }
        void RemoveColor(TKey key);
    }

    
}
