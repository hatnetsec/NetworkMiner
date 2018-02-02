using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser {
    public interface IPopularityList<TKey,TValue> {

        //delegate void PopularityLostEventHandler(TKey key, TValue value);
        event PopularityList<TKey, TValue>.PopularityLostEventHandler PopularityLost;

        TValue this[TKey key]{get; set;}

        int Count { get; }

        void Add(TKey key, TValue value);
        bool ContainsKey(TKey key);
        void Remove(TKey key);
        IEnumerable<TValue> GetValueEnumerator();

        
    }
}
