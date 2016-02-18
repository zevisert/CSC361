Simple HTTP over TCP Client Server
Author: Zev Isert
CSC361 - Assignment 1

-----------------------------------
Building
-----------------------------------

- use make
    - all
    - client
    - server
    - clean

- All files in current directory

-----------------------------------
Running
-----------------------------------

====== CLIENT ======
- make compiles to ./simpleClient
    - execute with --help to print usage 
    - does argument validation
    - quick usage:
        ./simpleClient host[:port][/path/to/file]

====== SERVER ======
- make compiles to ./simpleServer
    - will run without args on port 9898 in current directory
    - execute with --help to print usage
    - does arguement validation
    - quick usage:
        ./simpleServer [port] [path/to/base/direcotry]
        - path can be relative

-----------------------------------
Examples
-----------------------------------

====== CLIENT ======

>>> $ ./simpleClient zevisert.ca/index.html         |    >>> $ ./simpleClient stackoverflow.com:80
---Reqest begin---                                  |    ---Reqest begin---
Host: zevisert.ca                                   |    Host: stackoverflow.com
GET /index.html HTTP/1.0                            |    GET / HTTP/1.0
                                                    |
---Request End---                                   |    ---Request End---
HTTP request sent, awaiting response...             |    HTTP request sent, awaiting response...
                                                    |
---Response Header---                               |    ---Response Header---
HTTP/1.1 200 OK                                     |    HTTP/1.1 200 OK
Date: Wed, 03 Feb 2016 06:48:44 GMT                 |    Date: Wed, 03 Feb 2016 19:18:55 GMT
Server: Apache/2.4.12                               |    Content-Type: text/html; charset=utf-8
Last-Modified: Thu, 21 Jan 2016 00:46:42 GMT        |    Connection: close
ETag: "261a75-7ab-529cd6fb59b2f"                    |    Set-Cookie: __cfduid=d976e...
Accept-Ranges: bytes                                |    Cache-Control: public...
Content-Length: 2088                                |    Expires: Wed, 03 Feb 2016 19:19:54 GMT
Connection: close                                   |    Last-Modified: Wed, 03 Feb 2016 19:18:54 GMT
Content-Type: text/html                             |    Vary: *
                                                    |    X-Frame-Options: SAMEORIGIN
                                                    |    X-Request-Guid: 900...
                                                    |    Set-Cookie: prov=421b6...
        ...                                         |    Server: cloudflare-nginx
                                                    |    CF-RAY: 26f07c05161c2a43-SEA
                                                    |    
---Response Body---                                 |    ---Response Body---
Received 2092 bytes. Print server reply [Y|N]:n     |    Received 245096 bytes. Print server reply [Y|N]:n



====== SERVER ======

>>> $ ./simpleServer 

------

>>> $ ./simpleServer 8080
