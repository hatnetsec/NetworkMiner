//  Copyright: Erik Hjelmvik, NETRESEC
//
//  NetworkMiner is free software; you can redistribute it and/or modify it
//  under the terms of the GNU General Public License
//

using System;
using System.Collections;
using System.Collections.Generic;
using System.Text;
using System.IO;

namespace PacketParser.CleartextDictionary {
    public class WordDictionary {
        private int longestWord;
        private int minWordLength;
        private BloomFilter bloomFilter;
        private BitArray byteLetters;//holds true if there is a letter at the position

        internal int LongestWord { get { return this.longestWord; } }
        public long WordCount {
            get {
                if (this.bloomFilter == null)
                    return 0;
                else
                    return this.bloomFilter.WordCount;
            }
        }

        public WordDictionary() {
            this.minWordLength=3;
            this.longestWord=0;
            this.byteLetters=new BitArray(1+Byte.MaxValue);
        }
        public void LoadDictionaryFile(string dictionaryFile) {
            //read the file and add data to good structures
            List<string> wordList=new List<string>();
            //System.IO.FileStream fileStream=new FileStream(Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath)+"\\"+dictionaryFile, FileMode.Open, FileAccess.Read);
            System.IO.FileStream fileStream=new FileStream(dictionaryFile, FileMode.Open, FileAccess.Read);
            StreamReader reader=new StreamReader(fileStream);

            while(!reader.EndOfStream) {
                string line=reader.ReadLine();
                //if(line.Contains(" ")) {
                    char[] separator={' ',',','.',' ','!','?','<','>','(',')','{','}','[',']','"','\''};
                    string[] words=line.Split(separator);
                    foreach(string s in words)
                        AddWord(s, wordList);
                /*}
                else
                    AddWord(line, wordList);*/
            }
            bloomFilter=new BloomFilter(wordList);
            //the file is now loaded
        }

        private void AddWord(string word, List<string> wordList) {
                if(word.Length>=this.minWordLength) {
                    wordList.Add(word.ToLower());
                    foreach(char c in word)
                        byteLetters[(byte)c]=true;
                    foreach(char c in word.ToUpper())
                        byteLetters[(byte)c]=true;
                    if(word.Length>this.longestWord)
                        this.longestWord=word.Length;
                }
        }

        internal bool HasWord(string word) {
            word=word.ToLower();
            if(word.Length>this.longestWord || word.Length<this.minWordLength)
                return false;
            return bloomFilter.HasWord(word);
        }
        internal bool IsLetter(byte b) {
            return byteLetters[b];
        }
    }
}
