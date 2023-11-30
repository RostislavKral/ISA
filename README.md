# Projekt DNS resolver - Síťové aplikace a správa sítí
## Autor - Rostislav Král (xkralr06) 19.11.2023
---
## Popis
Úlohou projektu bylo implementovat jednoduchý DNS resolver v jazyce C nebo C++, posílat dotazy typu A, AAAA a PTR na DNS server, které potom resolver naparsuje a vypíše odpovědi serveru uživateli. 

## Makefile

Příkaz `make` přeloží projekt.<br>
Příkaz `make test` přeloží projekt a spustí testy. (Pozor, smaže i spustitelný soubor)

## Spuštění aplikace
Použití: `dns [-r] [-x] [-6] -s server [-p port] adresa`

Pořadí parametrů je libovolné. Popis parametrů:

    -r: Požadována rekurze (Recursion Desired = 1), jinak bez rekurze.
    -x: Reverzní dotaz místo přímého.
    -6: Dotaz typu AAAA místo výchozího A.
    -s: IP adresa nebo doménové jméno serveru, kam se má zaslat dotaz.
    -p port: Číslo portu, na který se má poslat dotaz, výchozí 53.
    adresa: Dotazovaná adresa.

Příklad spuštění
`./dns -s 8.8.8.8 www.github.com -r`

0000:     0d a7 81 80 00 01 00 02 00 00 00 00 03 77 77 77<br>
0010:     06 67 69 74 68 75 62 03 63 6f 6d 00 00 01 00 01 <br>
0020:     c0 0c 00 05 00 01 00 00 08 9e 00 02 c0 10 c0 10 <br>
0030:     00 01 00 01 00 00 00 3c 00 04 8c 52 79 03 <br>

DNS HEADER: Authoritative: No, Recursive: Yes, Truncated: No<br>
Question section(1)<br>
  www.github.com., A, IN<br>
Answer section(2)<br>
  www.github.com, CNAME, IN, 2206, github.com<br>
  github.com, A, IN, 60, 140.82.121.3

Authority section (0)<br>
Additional section (0)<br>

---
## Rozšíření a omezení
### Rozšíření
- Vypisování dat v hexadecimálním formátu jako to má např. nástroj Wireshark.
- Program umí naparsovat mimo záznamy A, AAAA a PTR i záznamy typu NS.

### Omezení
- Testy lze spusti jen na referenčním serveru Merlin(popř. jakékoliv jiné aktuální linuxové distribuci, zkoušel jsem jen ubuntu 20.04), na Evě jsou zastaralé knihovny.

---
## Seznam odevzdaných souborů:
- googletest/
- Makefile
- README.md
- helpers.h
- helpers.cpp
- dns-resolver.h
- dns-resolver.cpp
- main.cpp
- manual.pdf