------------------------------Network Services ------------------------------

This Project was Done By Michael Hofmann.
Last update : 12/18/2020.

The management of options and reception of packets is done in the main.
Every protocols analyse is done in a file with its header.

There is a file (analyse_port.c) that deals with all application protocols,
and enable to keep on the project in the futur .

Fct_utilitaires.c is a file that contain all useful functions for
application protocols, such as translate with the ascii table.

Usually, each protocol has a function info that display its information,
and a function myprotocol_packet that deals with the size of the packers
and call the info function

This project isn't really commented as I didn't feel the need for it,
unless for some details of the documentation / structures 
I found online from the pcap Documentation.

------------------------------ How to launch the program ------------------------------

------------ Test files --------------------
the project contain a directory full of file to test the differents protocol with the
-o options

------------------------------ options ------------------------------
-i name_interface

If there isn't any, it just takes the first interface available and 
listen the packets.


-o name_file

It analyse packets from pcap files


-v level_verbosity      (verbosity = 1, 2 or 3)
enable the level of verbosity of the packets.
1 for low, 3 for a lot of details.
by default it shows all the details


------------------------------command example to launch it ------------------------------
A lot of file with tram example are in the test_files directory 

sudo ./bin/analyseur -o test_files/smtp_ipv6.cap




----------------------Brief details of some of the files-----------------------------





------------------------------main------------------------------

Deals with the options, and call either the function
for a file or for live listening.

verbosity is a global and extern variable that is 
used all the long in all the files.


------------------------------Liaison layer ------------------------------

------------------------------ Ethernet------------------------------

protocols known byt the program:

-ipv4
-ipv6
-arp



------------------------------Couche ip------------------------------

------------------------------ipv4 & ipv6------------------------------

protocols known:
-udp
-tcp


------------------------------Couche transport------------------------------
UDP and TCP call a function define in port.c that deals with all
differents application protocols.

  

------------------------------Couche application------------------------------

Protocols known:
-bootp
-dns
-ftp
-http
-imap
-pop3
-smtp
-telnet (not done yet)



