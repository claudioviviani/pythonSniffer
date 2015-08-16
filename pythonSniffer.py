# Python POP/IMAP Sniffer by Claudio Viviani
#
# http://www.homelab.it
# info@homelab.it
# homelabit@protonmail.ch
#
# https://www.facebook.com/homelabit
# https://twitter.com/homelabit
# https://plus.google.com/+HomelabIt1/
# https://www.youtube.com/channel/UCqqmSdMqf_exicCe_DjlBww
#
#
# Moduli - 0x1 - Questo modulo gestisce i socket di sistema
# http://docs.python.it/html/lib/module-socket.html
import socket
# Moduli - 0x2 - Questo modulo gestisce prametri e funzioni specifiche per il sistema
# http://docs.python.it/html/lib/module-sys.html
import sys
# Moduli - 0x3 - Questo modulo effettua conversioni tra i valori Python e le strutture C rappresentate come stringhe Python.
# Puo' venire impiegato per gestire dati binari memoprizzati su file o provienienti da una connessione di rete, 
# come esempio di sorgenti di dati, fra i tanti possibili.
# http://docs.python.it/html/lib/module-struct.html
from struct import *


banner='''
#############################
   Python POP/IMAP Sniffer
            by
      Claudio Viviani
#############################
'''
print(banner)
# Creo il socket utilizzando la funzione PF_PACKET e SOCK_RAW per operare al livello di device driver layer,
# rimanendo in ascolto su tutti i protocolli ETH_P_ALL (0x0003) con l'ordine dei byte da network a host (ntohs)
# https://it.wikipedia.org/wiki/Ordine_dei_byte
#
# E' necessario un account privilegiato (Administrator/root) per creare un un socket raw pf_packet
try:
    s = socket.socket( socket.PF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
 
    # Creo un ciclo infinito per raccogliere tutti i pacchetti che transitano dal device
    while True:
        # Nel socket creo un buffer per memorizzarci il pacchetto
        packet = s.recvfrom(65565)

        # I pacchetti arrivano come tuple, a noi interessano i dati presenti nella prima tupla [0]
        packet = packet[0]

        # Phisical Layer - 0x1 - I primi 14 byte di un frame ethernet compongono l'ethernet header e sono suddivisi in 3 parti:
        #
        # 1) Destination MAC Address (6 byte chars)
        # 2) Source MAC Address      (6 byte chars)
        # 4) Ether type o Protocollo (2 byte int)
        #
        # Rif: https://it.wikipedia.org/wiki/Frame_Ethernet
        #
        # Lunghezza frame interessata 6+6+2
        eth_length = 14

        # Del pacchetto prendo i primi 14 byte (Vedi commento Phisical Layer - 0x1 -)
        eth_header = packet[:eth_length]
        # Tramite la funzione unpack del modulo struct formatto i dati del pacchetto ricevuto da binario al formato desiderato.
        # (Per la tabella dei formatti fare riferimento al link nel commento Moduli - 0x3 -)
        # Seguendo la tabella dei formatti, utilizzo i parametri: 
        # 6s (dest macs - stringa di 6 byte)
        # 6s (source mac - stringa di 6 byte)
        # H  (ether type - intero di 2 byte) 
        #
        # Utilizzo il simbolo "!" per specificare che l'ordine dei byte del pacchetto binario e' big-endian.
        # I pacchetti di rete utilizzano l'ordine big-endian
        # https://it.wikipedia.org/wiki/Ordine_dei_byte
        eth = unpack('!6s6sH' , eth_header)
        #
        # Tramite la funzione ntohs del modulo socket converto l'ordine dei byte da network ad host
        # estrapolando il protocollo che si trova nella terza tupla (eth[2])
        eth_protocol = socket.ntohs(eth[2])
        #
        # Per debug faccio stampare a video il dest mac, source mac, e l'ether type (protocollo)
        # print 'Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol)

        # Considero solo il protocollo IP che viene classificato col valore intero 8
        if eth_protocol == 8 :

            # Per estrapolare l'ip header del pacchetto, prendo i 20 byte successivi all'ethernet,quindi da 14 al 34
            ip_header = packet[eth_length:20+eth_length]

            # Tramite la funzione unpack del modulo struct formatto i dati del pacchetto ricevuto da binario al formato desiderato.
            # (Per la tabella dei formatti fare riferimento al link nel commento Moduli - 0x3 -)
            iph = unpack('!BBHHHBBH4s4s' , ip_header)

            # Per estrapolare dal pacchetto il valore di lunghezza dell'ip header devo:
            # 1) Selezionare la prima tupla di 1 byte (8bit) dove trovero' i valori dell'ip version(4 bit)+header length(4bit)
            #    https://it.wikipedia.org/wiki/IPv4
            version_ihl = iph[0]
            # 2) Tramite gli operatori bitwise, in particolare con l'opratore AND (&), 
            #    estrapolo gli ultimi 4 bit(0xF = 1111) dove e' presente il campo header length
            #    http://docs.python.it/html/ref/bitwise.html
            iph_length = version_ihl & 0xF
            # 3) Moltiplico la lunghezza per 4 per avere il valore in byte
            iph_length = iph_length * 4

            # Per estrapolare il protocollo dal pacchetto, seleziona la quinta tupla
            protocol = iph[6]
            # Per selezionare il source e destination address seleziono la settima e ottava tupla convertendola nella rappresentazione 
            # standard in quartine-puntate tramite la funzione inet_ntoa del modulo socket.
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);


            # Considero solo il protocollo TCP che viene classificato col valore intero 6
            if protocol == 6 :

                # Per estrapolare il tcp header del pacchetto, prendo i 20 byte successivi all'ip header,quindi da 34 al 54
                tcp_header = packet[34:54]

                # Tramite la funzione unpack del modulo struct formatto i dati del pacchetto ricevuto da binario al formato desiderato.
                # (Per la tabella dei formatti fare riferimento al link nel commento Moduli - 0x3 -)
                tcph = unpack('!HHLLBBHHH' , tcp_header)

                # Per estrapolare la source eport dal pacchetto, seleziono la prima tupla 
                source_port = tcph[0]
                # Per estrapolare la destination port dal pacchetto, seleziono la seconda tupla
                dest_port = tcph[1]
                # Per estrapolare il sequence number dal pacchetto, seleziono la terza tupla
                sequence = tcph[2]
                # Per estrapolare l'acknowledgement number dal pacchetto, seleziono la quarta tupla
                acknowledgement = tcph[3]
                # Per estrapolare dal pacchetto il valore di lunghezza del tcp header devo:
                # 1) Selezionare la quinta tupla di 1 byte (8bit) dove trovero' i valori del Data offset(4 bit)+reserved(4bit)
                #    https://it.wikipedia.org/wiki/Transmission_Control_Protocol
                doff_reserved = tcph[4]
                # 2) Tramite gli operatori bitwise, in particolare l'operatore shift (>>),
                #    estrapolo i primi 4 bit dove e' presente il campo data offset
                tcph_length = doff_reserved >> 4
                # Moltiplico la lunghezza per 4 per avere il valore in byte
                tcph_length = tcph_length * 4

                # Calcolo l'inizio dei dati del pacchetto sommando i byte dell'ethernet, ip e tcp lenght
                h_size = eth_length + iph_length + tcph_length
                data = packet[h_size:]

                # Intercetto solo la source port e destination port pop3/imap (110/143 tcp ports)
                if dest_port == 110 or source_port == 110 or dest_port == 143 or source_port == 143: 

                    # Se i dati non sono vuoti li stampo a video
                    if data != "":
                        print 'Source IP   : ' +str(s_addr)
                        print 'Source Port : ' +str(source_port)
                        print 'Dest IP     : ' +str(d_addr)
                        print 'Dest Port   : ' +str(dest_port)
                        print 'Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement)
                        print 'Data : ' + data

except socket.error , msg:
    print 'Errore nella creazione del socket: %s' %msg[1]
    sys.exit()
    
except KeyboardInterrupt:
    print "Sniffer interrotto dall'utente "
    sys.exit()
