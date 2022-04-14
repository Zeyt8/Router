Foca Bogdan 324CD

Am rezolvat cerintele:
    -Protocolul ARP
    -Procesul de dirijare
    -Protocolul ICMP
    -BONUS: actualizare sumei de control incrementale

In main extrag headerele din pachetul primit.
Tipul pachetului(ARP sau ICMP) este stabilit din existenta headerelor de ARP sau ICMP.
Se apeleaza functiile handleARP sau handleICMP care returneaza un bool. Acest bool este fals in cazul in care pachetul trebuie droppuit sau in cazul in care s-a terminat functionalitatea lui si nu este nevoie de el mai departe.
Daca boolul este adevarat, codul ajunge in handleForwarding unde pachetul este forwarded mai departe.

Handle ARP:
    Se stabileste daca pachetul ARP este de tipul request sau reply verificand valoarea din arp_hdr->op.
    Daca este de tipul request, atunci se trimite un arp reply la sursa de unde a venit requestul.
    Daca este de tipul reply, se verifica daca exista vreun pachet in coada de pachete pastrate. Daca exista, le verific checksumul(ttl-ul nu, intrucat a fost deja updatat cand l-am adaugat in coada). Daca totul este ok, se gaseste ruta si daca exista updatez ethernet_headerul cu macul aferent si trimit pachetul.

Handle ICMP:
    Se verifica ttl si icmp checksum. Daca pachetul este pentru routerul curent si este de tipul echo request atunci trimit un ICMP inapoi la sursa.

Handle Forwarding:
    Se verifica ttl si checksum. Ttl este updatat si checksumul la fel. Se cauta o ruta si daca nu exista se trimite un ICMP error inapoi la sursa.
    Se cauta adresa mac necesara in tabela ARP. Daca nu exista atunci pachetul este introdus in coada si se trimite un ARP broadcast.
    Daca este gasita o adresa mac, se updateaza ethernet headerul cu mac-ul urmatorului hop si se trimite pachetul.

TTL Decrement Checksum:
    Updatarea checksumului in urma modificarii ttl.
    Logica este preluata de aici: https://datatracker.ietf.org/doc/rfc1624/

Get route:
    Parcurge liniar tabela de routare. In comenturi se afla o incercare de cautare binara. Tabela este sortata la inceput cu un merge sort in functie de prefix si masca.

Send ARP si ICMP:
    Creeaza headerele necesare din argumentele date. Creeaza un pachet nou in care introduce aceste headere si il trimite.