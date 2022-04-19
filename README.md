# Network Scanner

By [Michael Hofmann](https://github.com/Mis0ko) <br/>
Last update : 12/18/2020.

## Overview 

The options management and reception of packets are done in the main.
Every protocol analysis is done in a file with its header.

There is a file ***(analyse_port.c)*** that deals with all application protocols,
and enable to keep on the project in the futur .

***Fct_utilitaires.c*** is a file that contains every useful functions for
application protocols, such as translate with the ascii table.

Usually, each protocol has a function ***info*** that display its information,
and a function ***myprotocol_packet*** that deals with the size of the packers
and call the info function.

This project isn't really commented as I didn't feel the need for it,
unless for some details of the documentation / structures 
I found online from the pcap Documentation.

## Program Options

### Test files
This project contains a directory full of file to test the differents protocol with the
`-o options`

### options 

`-i name_interface`

If there isn't any interfaces, it just takes the first interface available and 
listen the packets.


`-o name_file`

Analyse packets from pcap files


`-v level_verbosity`      (verbosity = 1, 2 or 3)<br/>
enable the level of verbosity of the packets.<br/>
1 for low, 3 for a lot of details.<br/>
By default it shows all the details<br/>


## How to Launch it

A lot of file with trames examples are in the test_files directory 

To launch the project with one of them, just use :
`sudo ./bin/analyseur -o test_files/smtp_ipv6.cap`

# Brief details of some of the files 


## Main

Deals with the options, and call either the function for a file or for live listening.<br/>

Verbosity is a global and extern variable used all along throughout files.

## Data-Link layer

### Ethernet

Protocols dealed by the program :

- ipv4
- ipv6
- arp

## IP Layer (Network)

### IPV4 & IPV6

Protocols dealed by the program :
- udp
- tcp


## Transport Layer 

UDP and TCP call a function define in port.c that deals with all differents application protocols.

  

## Application Layer

Protocols dealed by the program :
- bootp
- dns
- ftp
- http
- imap
- pop3
- smtp
- telnet (not totally done yet)



