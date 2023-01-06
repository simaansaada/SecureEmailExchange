using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

namespace Cryptography
{
    public class EmailMessage
    {
        public string Subject { get; internal set; }
        public string Message { get; internal set; }

        public EmailMessage(string Subjcet, string Message)
        {
            this.Subject = Subject;
            this.Message = Message;
        }

        public static byte[] Serialize(EmailMessage objToSerialize)
        {
            MemoryStream s = new MemoryStream();
            BinaryFormatter b = new BinaryFormatter();
            b.Serialize(s, objToSerialize);
            return s.GetBuffer();
        }

        public static EmailMessage DeSerialize(byte[] serializedObject)
        {
            MemoryStream s = new MemoryStream(serializedObject);
            BinaryFormatter b = new BinaryFormatter();
            EmailMessage result = (EmailMessage)b.Deserialize(s);
            return result;
        }
     
    }
}
