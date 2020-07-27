# IPK - projekt 1 - HTTP resolver doménových mien 

**login: xsocho14**
**dátum: 08.03.2020**

Cieľom projektu bolo vytvoriť server komunikujúci HTTP protokolom. Úlohou serveru je prekladať doménové mená na IP adresy a opačne. Na preklad je používaný lokálny resolver stanice, na ktorom je server spustený. Server podpodruje dve metódy: *GET* a *POST*. Riešenie je implementované v jazyku *Python* a nachádza sa v súbore *server. py*.

## Spustenie
Skript sa spúšťa pomocou príkazu:
```
make run PORT=1234
```
Pre spustenie je potrebný priložený *Makefile* obsahujúci názov spúšťaného súboru a verziu používaného jazyka. V prípade, že je zadaný nesprávny príkaz alebo číslo portu je mimo rozsahu <1024;65535>, skript vypíše chybovú hlášku a je ukončený pomocou príkazu *sys.exit()*.

## Implementácia serveru
Server je implementovaný použitím knižnice soketov.
```
import socket 
```
Po vytvorení soketu, server počúva na danom porte a beží v nekonečnej smyčke. Týmto je zabezpečené, že nie je ukončený po naviazaní jedného spojenia, ale je aktívny až kým nedostane príkaz od používateľa. Prerušený je signálom *SIGINT*, ktorý používateľ vygeneruje stlačením: CTRL + C.
Keďže server môže obsluhovať viacero klientov naraz, používa neblokujúci mód. Pri vytvorení spojenia s novým klientom je inicializovaná dvojica, kľúč a maska. Vďaka tejto dvojici je zabezpečené oddelené spracovanie dát pri jednotlivých klientoch. Každý soket má možnosť zapisovať aj čítať dáta. Vykonávaná operácia je zabezpečená podľa hodnoty v premennej *mask*. Odpoveď je na klienta poslaná vo formáte:
```
'HTTP/1.1' + ' ' + code + ' ' + description + ' ' + '\r\n\r\n' + answer
```
- **code** - návratová hodnota odpovede
- **description** - popis návratovej hodnoty
- **answer** - preklad IP adresy alebo doménového mena

## Kontrola formátu požiadavok
Po príchode požiadavky, je kontrolovaný jej formát a štruktúra. Kontrola je primárne vykonávaná pomocou vstavaných funkcií *split()* a *strip()*. Kontrolovaná je zadaná metóda, správny formát url, parametrov a správna HTTP verzia. Po vykonaní kontroly sú potrebné časti požiadavky odoslané do funkcií na preklad doménových mien a IP adries. Funkcie sú rozdelené podľa metódy (*GET* alebo *POST*) 

## Resolver
Na preklad sú používané API funkcie.  *Getaddrinfo()* pre získanie IP adresy. Vstupným parametrom je doménové meno, port a *AF_INET* pre získanie výlučne IPv4 adries. Pre získanie doménového mena bola použitá funkcia *gethostbyaddr()* so vstupným parametrom IPv4 adresy. V tejto časti skript ošetruje, či je k doménovému menu zadaný typ *A* a k IP adrese typ *PTR*. V prípade nesprávneho spojenia nastáva chyba *400 BadRequest* 


## Chybové kódy
Ak dôjde k chybe či už počas overovania formátu, zisťovania IP adresy alebo doménového mena, tak je zavolaná jedna s funkcií ošetrujúcich chybu:
- **Error400()** - funkcia je volaná, ak je prijatý nesprávny formát alebo štruktúra požiadavku,
- **Error404()** - funkcia je volaná, ak dôjde k chybe pri preklade domenénového mena alebo IP adresy. Doménové meno je neplatné. IP adresa nemá záznam v tabuľke alebo nie je na ňu registrované doménové meno,
- **Error405()** - funkcia je volaná v prípade nepodporovanej metódy. 















