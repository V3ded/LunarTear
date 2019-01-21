# Lunar Tear


## Information:
<b>Tool name:</b><i> Lunar Tear</i><br>
<b>Version:</b> 2.0 <br>
<b>Author:</b> <i>@V3ded</i><br>
<b>Summary:</b> A multi-threaded <i>TCP SYN</i>/<i>UDP</i> stresser<br>

## Installation:
`apt-get install gcc`<br> 
`gcc LunarTear.c -o LunarTear -pthread -lm`

## Usage:
```console
$ ./LunarTear --help
Usage: LunarTear [OPTION...]
LunarTear is a UDP/TCP SYN stresser

 REQUIRED OPTIONS:
  -h, --host=HOST            [*] Host to flood
  -p, --port=PORT            [*] Port to flood on the host
  -t, --threads=NUM          [*] Amount of threads to use [MAX = 100]

 CHOOSE ONE:
      --tcp                  [*] Using TCP SYN flooding
      --udp                  [*] Using UDP flooding

 OPTIONAL OPTIONS:
      --amount=NUM           Sends n amount of packets where n = amount. (Only
                             a rough estimate...)
      --spoof-ip=IP          Spoofs originating IP (Only works on LAN...)
      --spoof-port=PORT      Spoofs originating PORT (Only works on LAN...)
  -v, --verbose              Verbose output

  -?, --help                 Give this help list
      --usage                Give a short usage message
  -V, --version              Print program version

Mandatory or optional arguments to long options are also mandatory or optional
for any corresponding short options.
```
