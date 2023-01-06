using Cryptography;
using System;
using System.Net;
using System.Net.Sockets;

namespace MailServer
{
    class Program
    {
        static TcpListener server = null;

        static void Main(string[] args)
        {
            Console.WriteLine("Starting the mail server...");
            Camelia128CFB cammelia = new Camelia128CFB("cipherkey");
            Console.WriteLine(cammelia.Encrypt("text"));
            Console.ReadLine();
            //MailServerBuilder();
        }

        static void MailServerBuilder()
        {
            try
            {

                Int32 port = 25; // the default smtp port
                IPAddress localAddr = IPAddress.Parse("0.0.0.0"); // any ip does host machine have.

                // TcpListener server = new TcpListener(port);
                server = new TcpListener(localAddr, port);

                // Start listening for client requests.
                server.Start();
                Console.WriteLine("Listening on port {0}:{1} ", localAddr.MapToIPv4().ToString(), port);
                // Buffer for reading data
                Byte[] bytes = new Byte[256];
                String data = null;
                while (true)
                {
                    Console.Write("Waiting for a connection... ");

                    // Perform a blocking call to accept requests.
                    // You could also use server.AcceptSocket() here.
                    using TcpClient client = server.AcceptTcpClient();
                    Console.WriteLine("Connected!");

                    data = null;

                    // Get a stream object for reading and writing
                    NetworkStream stream = client.GetStream();

                    int i;

                    // Loop to receive all the data sent by the client.
                    while ((i = stream.Read(bytes, 0, bytes.Length)) != 0)
                    {
                        // Translate data bytes to a ASCII string.
                        data = System.Text.Encoding.ASCII.GetString(bytes, 0, i);

                        // Process the data sent by the client.
                        //data = data.ToUpper();

                        byte[] msg = System.Text.Encoding.ASCII.GetBytes(data);
                        EmailMessage message = EmailMessage.DeSerialize(msg);
                        Console.WriteLine("Received: {0}", message.Message);
                        // Send back a response.
                        //stream.Write(msg, 0, msg.Length);
                        Console.WriteLine("Sent: {0}", data);
                    }
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine(e);
            }

        }
    }
}
