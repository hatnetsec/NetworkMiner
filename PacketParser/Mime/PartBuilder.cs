using System;
using System.Collections.Generic;
using System.Text;

namespace PacketParser.Mime {
    static class PartBuilder {

        public static IEnumerable<MultipartPart> GetParts(byte[] mimeMultipartData, string boundary) {
            System.IO.Stream stream=new ByteArrayStream(mimeMultipartData, 0);
            Mime.UnbufferedReader reader=new UnbufferedReader(stream);
            return GetParts(reader, boundary);
        }
        public static IEnumerable<MultipartPart> GetParts(Mime.UnbufferedReader streamReader, Encoding customEncoding = null) {
            long startPosition = streamReader.BaseStream.Position;
            //find out the boundary and call the GetParts with boundary
            System.Collections.Specialized.NameValueCollection attributes;
            MultipartPart.ReadHeaderAttributes(streamReader.BaseStream, streamReader.BaseStream.Position, out attributes);
            if (attributes["charset"] != null) {
                try {
                    customEncoding = Encoding.GetEncoding(attributes["charset"]);
                }
                catch { }
            }
            string boundary = attributes["boundary"];
            if (boundary != null) {
                streamReader.BaseStream.Position = startPosition;
                //int partsReturned = 0;
                foreach (MultipartPart part in GetParts(streamReader, boundary, customEncoding)) {
                    yield return part;
                    //partsReturned++;
                }
                //if(partsReturned == 0)//return a single part
                //    yield return new MultipartPart(streamReader.BaseStream, streamReader.BaseStream.Position, (int)(streamReader.BaseStream.Length - streamReader.BaseStream.Position), customEncoding);
            }
            else {
                //return a single part
                yield return new MultipartPart(streamReader.BaseStream, streamReader.BaseStream.Position, (int)(streamReader.BaseStream.Length - streamReader.BaseStream.Position), customEncoding);
                //yield break;
            }

        }
        public static IEnumerable<MultipartPart> GetParts(Mime.UnbufferedReader streamReader, string boundary, Encoding customEncoding = null) {

            string interPartBoundary="--"+boundary;
            string finalBoundary="--"+boundary+"--";
            while(!streamReader.EndOfStream){
                long partStartPosition=streamReader.BaseStream.Position;
                int partLength=0;
                string line=streamReader.ReadLine(200, customEncoding);
                while(line!=interPartBoundary && line!=finalBoundary){
                    partLength=(int)(streamReader.BaseStream.Position-2-partStartPosition);//-2 is in order to remove the CRLF at the end
                    line=streamReader.ReadLine(200, customEncoding);
                    if(line==null) {
                        yield break;//end of stream
                        //break;
                    }
                }
                long nextPartStartPosition=streamReader.BaseStream.Position;

                if(partLength>0){
                    byte[] partData=new byte[partLength];
                    streamReader.BaseStream.Position=partStartPosition;
                    streamReader.BaseStream.Read(partData, 0, partData.Length);
                    MultipartPart part = new MultipartPart(partData, customEncoding);

                    if(part.Attributes["Content-Type"]!=null && part.Attributes["Content-Type"].Contains("multipart") && part.Attributes["boundary"]!=null && part.Attributes["boundary"]!=boundary) {
                        foreach(MultipartPart internalPart in GetParts(part.Data, part.Attributes["boundary"]))
                            yield return internalPart;
                    }
                    else
                        yield return part;
                }
                
                streamReader.BaseStream.Position=nextPartStartPosition;
                if(line==finalBoundary)
                    break;
            }
        }
    }
}
