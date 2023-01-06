using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Cryptography;

namespace SecureMailExchange
{
    class Program
    {
        static string serverIPaddress = "127.0.0.1";
        static int serverport = 25;
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");
            ConnectToServer();
        }

        static EmailMessage getMessageFromUser(){
            string content = "";
            string subject = "";
            Console.Write("Message Subjcet:");
            subject = Console.ReadLine();
            Console.Write("Message Content:");
            content = Console.ReadLine();
            EmailMessage mesage = new EmailMessage(subject,content);
            return mesage;
        }
        static void ConnectToServer()
        {
            Socket tempSocket =
            new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPAddress address =  System.Net.IPAddress.Parse(serverIPaddress);
            IPEndPoint endPoint = new IPEndPoint(address, serverport);
            tempSocket.Connect(endPoint);
            if (tempSocket.Connected)
            {
                EmailMessage messageToSend = getMessageFromUser();
                tempSocket.Send(EmailMessage.Serialize(messageToSend));
                //this.tcpSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive,true);
                Console.WriteLine("Successfully connected.");
                Console.ReadLine();
            }
            else
            {
                Console.WriteLine("Error.");
            }
        }
    }
}
