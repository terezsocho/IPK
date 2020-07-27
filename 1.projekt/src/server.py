#!/usr/bin/env python3

#####################################
# Predmet: IPK	      		    #
# Projekt: HTTP Resolver    	    #
# Meno Priezvisko: Terezia Sochova  #
# Login: xsocho14		    #
# Datum: 03.03.2020		    #
#####################################

import sys
import socket
import selectors
import types

sel = selectors.DefaultSelector()
host = "127.0.0.1"

# overenie spravneho spustenia
if len(sys.argv) != 3:
    sys.exit('ERROR: wrong number of arguments.\nCORRECT FORMAT: make run PORT=<number>\n')
else:
    port = int(sys.argv[2])
    if port < 1024 or port > 65535:
        sys.exit('ERROR: wrong number of port.\nALLOWED RANGE: 1024-65535')
   
# funkcia ktora kontroluje format vstupnych queries
# parsuje vstupne url a podla typu ho spracuvava
# dalej posiela udaje do funkcii ktore sluzia ako reseolver
def ParseQuery(data):
    query = data.splitlines()[0]#zoberie prvy riadok query 
    query = query.split()
    if len(query) != 3:#riadok obsahuje dve medzery
        return Error400()
    else:    
        operation = query[0] #GET|POST
        url = query[1]
        protocol = query[2] #HTTP/1.1
        if operation == 'GET'and protocol == 'HTTP/1.1':
            url = url.split("?")#na oddelenie /resolve a url
            if len(url) != 2:
                return Error400()
            else:    
                inputURL = url[0]
                arguments = url[1]      
                if inputURL == '/resolve':
                    arguments = arguments.split("&")#ziskanie argumentov/premennych
                    if len(arguments) != 2:
                        return Error400()
                    else:    
                        tmp_name = arguments[0]
                        tmp_typ = arguments[1]
                        tmp_name = tmp_name.split("=")# ziskanie hodnoty name
                        if len(tmp_name) != 2 or tmp_name[0] != 'name':
                            return Error400()
                        else:
                            name_addr = tmp_name[1]
                            tmp_typ = tmp_typ.split("=")#ziskanie hodnoty type
                            if len(tmp_typ) != 2 or tmp_typ[0] != 'type':
                                return Error400()
                            else: 
                                typ = tmp_typ[1]
                                # ak je platny prikaz GET tak posielam hodnoty do resolvera                      
                                return ResolveGET(name_addr, typ)           
                else: #not /resolve
                    return Error400()
        elif operation == 'POST'and protocol == 'HTTP/1.1':
            inputURL = url
            if inputURL == '/dns-query':
                seq = data.split("\r\n\r\n", 1)#oddelenie hlavicky a tela
                if len(seq) != 2:
                    return Error400()
                else:
                    dns_data = seq[1]#posielam telo metody POST na spracovanie
                    return ResolvePOST(dns_data)                    
            else:
                return Error400()
        else:
            return Error405() # nepotporovana metoda (ina ako GET|POST)

############ ERROR CODES ############# 
#  error kod ak je zadana ina operacia ako GET a POST
def Error405():
    answer = "405 Method Not Allowed.\n"
    code = "405"
    description = "Method Not ALlowed"    
    return answer, code, description

# error kod ak je zadane nespravne vstune URL,
# nespravne alebo chybajuce parametre,
# nespravna kombiacia adresa + A alebo domenove meno + PTR 
def Error400():
    answer = "400 Bad Request.\n"
    code = "400"
    description = "Bad Request"
    return answer, code, description
    
# error kod ak je zadana neplatna IP adresa
# ak na IP adresu nieje registrovane domain name
def Error404():
    answer = "404 Not Found.\n"
    code = "404"
    description = "Not Found"  
    return answer, code, description

# kontrola formatu ci sa jedna o IP adresu alebo domenove meno
def CheckFormat(var):
    addr = var
    if(len(var.split('.')) == 4):
        try:
            socket.inet_aton(addr)
            return 1
        except:
            return 0 
    else:        
        return 0    

# funkcia ktora preklada IP adresu na 
# domenove meno pre metodu GET a naopak
# dostava adresu/meno a typ(A | PTR)
def ResolveGET(ADDRorNAME, AorPTR):
    if len(ADDRorNAME) != 0 and len(AorPTR) != 0:# obe premenne su naplnene
        ip_name = CheckFormat(ADDRorNAME) 
        if AorPTR == 'A' and ip_name == 0:#spravna kombinacia domenove meno a typ:A
            try: #preklad pomocou getaddrinfo
                addrInfo = socket.getaddrinfo(ADDRorNAME, 80, family=socket.AF_INET, proto=socket.IPPROTO_TCP)              
            except socket.gaierror:#adresa nie je najdena tak je to exception
                return Error404()#NOT FOUND
            else:    
                addrInfo = addrInfo[0]
                addrInfo = addrInfo[4]
                addrInfo = addrInfo[0]
                answer = ADDRorNAME + ':' + AorPTR + '=' + addrInfo + '\n'
                code = '200'
                description = 'OK'
                return answer, code, description                          
        elif AorPTR == 'PTR'and ip_name == 1:#spravna kombinacia IP adresa a typ:PTR
            try:# preklad pomocou gethostbyaddr
                nameInfo = socket.gethostbyaddr(ADDRorNAME) 
            except socket.herror:
                return Error404()
            else:           
                nameInfo = nameInfo[0]
                #<IP_ADRESA>:PTR=<DOMENOVE_MENO>
                answer = ADDRorNAME + ':' + AorPTR + '=' + nameInfo + '\n'
                code = '200'
                description = 'OK'
                return answer, code, description                                            
        else:
            return Error400() #nespravny typ        
    else:
       return Error400()  #neobsahuje premenne
# funkcia na preklad ip adries na mena a opacne
# pri metode POST
# vysledne zaznamy su v poli 
def ResolvePOST(lines):
    if not lines.strip():
        return Error400()
    # rozdeluj podla riadkov
    tmp_lines = lines.split("\n")
    n = 0
    for l in tmp_lines:
        tmp_lines[n] = l.strip()
        n = n + 1
        
    if tmp_lines[-1] == '':
        tmp_lines.pop(-1)
    list_answers = ['end']
    boolean = True# ak nie je ani jeden riadok platny tak ostava TRUE
    i = 0
    for line in tmp_lines:
        line = line.strip()#odstaran zbytocne medzery
        if not line.strip():#ak je to prazdny riadok
           return Error400()
        tmp_answer = line.split(":")
        if len(tmp_answer) != 2:
           pass
        else:
            ADDRorNAME = tmp_answer[0]
            AorPTR = tmp_answer[1]
            ADDRorNAME = ADDRorNAME.strip()#odstranenie whitespaces
            AorPTR = AorPTR.strip() #odstranenie whitespaces
            if len(ADDRorNAME) != 0 and len(AorPTR) != 0:
                ip_name = CheckFormat(ADDRorNAME)#kontrola formatu 
                if AorPTR == 'A': # typ A
                    if ip_name == 0: # format domenoveho mena 
                        try:
                            addrInfo = socket.getaddrinfo(ADDRorNAME, 80, family=socket.AF_INET, proto=socket.IPPROTO_TCP)              
                        except socket.gaierror:
                            pass
                        else:    
                            addrInfo = addrInfo[0]
                            addrInfo = addrInfo[4]
                            addrInfo = addrInfo[0]
                            # <DN>:A=<IPadresa>
                            answer = ADDRorNAME + ':' + AorPTR + '=' + addrInfo 
                            list_answers.insert(i, answer)#vlozenie jedneho vysledku do pola
                            boolean = False# zrusenie ze bol aspon jeden zaznam spravny
                elif AorPTR == 'PTR':# typ:PTR
                    if ip_name == 1: #format IP adresa
                        try:
                            nameInfo = socket.gethostbyaddr(ADDRorNAME)         
                        except socket.herror:
                            pass
                        else:           
                            nameInfo = nameInfo[0]
                            answer = ADDRorNAME + ':' + AorPTR + '=' + nameInfo 
                            list_answers.insert(i, answer)
                            boolean = False
                else:
                    return Error400() 
            else:
                return Error400()
        i = i + 1   
    
    if boolean:
        return Error404()#not found ziadny zaznam nie je spravny
    else:
        list_answers.remove('end')
        final_answer = ''
        # z pola do viacriadkovej premennej
        for convert_list in list_answers:
            final_answer = final_answer + convert_list + '\n'
        code = "200"
        description = "OK"   
        return final_answer, code, description 

def accept_wrapper(sock):
    conn, addr = sock.accept()  #pripraveny na primanie dat
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")#vytvorime objekt pre ulozenie dat
    events = selectors.EVENT_READ | selectors.EVENT_WRITE # povolime zapisovanie a citanie
    sel.register(conn, events, data=data)

# funkcia ktora obsluhuje citanie a zapisovanie dat
def service_connection(key, mask):
	#mask : maska pripravenej opreracie
    sock = key.fileobj #socket objekt
    data = key.data 
    # log sucin ak je aktivna operacia read
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)  # prijmanie dat
        if recv_data:
            data.outb += recv_data
        else:#ak je prerusene spojenie klientom
            sel.unregister(sock)
            sock.close()
    # ak je aktivna operacia write        
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            parse = data.outb
            parse = parse.decode("utf-8")# decodovanie dat z 'b na utf-8
            answer, code, description = ParseQuery(parse)#posielanie dat na spracovanie
            answer = 'HTTP/1.1' + ' ' + code + ' ' + description + '\r\n\r\n' + answer
            data.outb = answer.encode() # data vo formate 'b 
            sent = sock.send(data.outb)  # data sa posielaju na klienta
            data.outb = data.outb[sent:]
            sel.unregister(sock)#prerusene spojenie s klientom
            sock.close()

lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)#vytvorenie socketu
lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)#opatovne pripojenie bez cakania
lsock.bind((host, port))
lsock.listen()
print("Server is listening on", (host, port))
lsock.setblocking(False) # neblokujuci mod
sel.register(lsock, selectors.EVENT_READ, data=None)
#registrovanie socketu lsock(server) na citanie dat

try:
    while True:# smycka pre neustale pocuvanie az do prerusenia SIGINT
        events = sel.select(timeout=None)
        # key a mask pre kazdy socket
        for key, mask in events:#events obsahuje pole key a mask
            if key.data is None:
                accept_wrapper(key.fileobj)
            else:
                service_connection(key, mask)
except KeyboardInterrupt:
    print('\nCTRL + C was pressed. Exiting Server')
finally:
    sel.close()#
