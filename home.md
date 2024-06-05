# Attacchi a Kerberos: <br> AS-REP roasting e Network Sniffing di AS-REQ + Password Cracking

Report per il corso di Cybersecurity [446MI], Università degli Studi di Trieste
<div style="display: flex; justify-content: space-between;">
    <div style="text-align: right;"> Anna Pascali, IN2000235  </div>
</div>


## Introduzione 
Il presente elaborato è volto alla dimostrazione di un attacco a kerberos, in particolare verranno illustrati:
- AS-REP roasting 
- Network Sniffing di AS-REQ e Password Cracking (per un utente con preauthentication)

A tale scopo è stato creato il dominio "mynetwork.local" su una macchina virtuale su cui è stato installato Windows Server 2022. 

### Macchine Virtuali utilizzate
Per eseguire la demo verranno utilizzate 3 macchine virtuali (VM - Virtual Machine):
- VM su cui ho installato Windows Server 2022. Questo nodo svolge il ruolo di Domain Controller (DC) per il dominio “mynetwork.local”, che è stato creato allo scopo di eseguire la demo. 
- VM su cui ho installato Windows 10 for Workstations; fa parte del dominio che ho creato. È il nodo da cui un utente inserito nel dominio eseguirà interactive logon in questa demo. 
- Kali linux è la macchina a disposizione dell’attaccante.

### Presentazione del Dominio 
Sulla VM con Windows Server 2022 è stato installato e configurato Windows Active Directory Domain Services. Inoltre ho installato e configurato i servizi DNS e DHCP. Utilizzando il DHCP ho assegnato indirizzi IP statici, all’interno di un range prefissato, ai nodi facenti parte dell’organizzazione. In particolare l’indirizzo IP del nodo su cui è presente il DC è 192.168.1.233; alla VM con Windows 10 è stato assegnato l’indirizzo IP 192.168.1.137. <br>
Al dominio “mynetwork.local” appartengono vari utenti, alcuni dei quali fanno parte di gruppi. Di rilievo è, ad esempio, l’utente Mario, il cui account è stato configurato con “Do not require Kerberos preauthentication”, come si evince dalla figura riportata. Questo assume particolare importanza per portare a termine il AS-REP roasting. 

<img src="images/Mario.png" alt="Account di Mario" width="500"> _Figura 1: Account di Mario, non richiede preauthentication_

Del dominio fanno parte anche altri utenti con pre authentication, uno dei quali eseguirà un interactive logon nella seconda parte della demo.


### Threat Model
Il threat model che verrà adottato è il seguente. Si suppone che l’attaccante:
- abbia informazioni sulla struttura di rete, quindi conosca l'indirizzo IP del nodo su cui è presente il Domain Controller (DC) e il range degli indirizzi IP assegnati ai nodi appartenenti al dominio; 
- sia in grado di comunicare con le macchine del dominio, quindi possa aprire connessioni TCP con queste.


&nbsp;

## AS-REP roasting

### Contesto
Questo tipo di attacco ha come presupposto il fatto che all’interno del dominio preso in considerazione ci sia almeno un utente il cui account è configurato con “Do not require Kerberos preauthentication”. L’attaccante, interrogando il DC, viene a conoscenza di quali siano gli utenti che hanno questo tipo di configurazione, il che significa che per contattare l’Authentication Service (AS), e ottenere un TGT (Ticket Granting Ticket), il loro AS-REQ non deve essere criptato con la chiave che deriva in maniera deterministica dal hash della loro password. Viene inviato un AS-REQ in chiaro al DC, il quale risponderà con un AS-REP che contiene, oltre al TGT per quell’utente, una parte di messaggio criptata con la chiave dell’utente. Ne consegue che la risposta del DC costituisce guessing material e permette di eseguire un password cracking attack.


### Esecuzione dell’attacco
In questa demo verrà utilizzato lo script python GetNPUsers, che appartiene al toolkit Impacket (una raccolta di classi python per lavorare con i protocolli di rete). Tramite LDAP queries, GetNPUsers contatta il DC per verificare se gli username che passiamo in un file di testo corrispondono a utenti inseriti nel dominio considerato e, in particolare se, fra questi, qualcuno non richiede preauthentication. Una volta trovato un utente che soddisfi questi requisiti, lo script costruisce un AS-REQ a suo nome da inviare in chiaro al DC, il quale risponderà con un AS-REP contente il TGT e una parte di messaggio criptata nella chiave dell'utente. 

![The Markdown Mark](images/impacket.png)
_Figura 2: Esecuzione e risultato di GetNPUsers_

Per eseguire questo comando è necessario:
- avere a disposizione un file di testo, in figura denominato names.txt, che contenga un elenco di potenziali username del dominio;
- scegliere un dominio, in figura indicato con MYNETWORK;
- conoscere l'indirizzo IP del nodo su cui è presente il DC, qui 192.168.1.233. Questo è reso possibile dal threat model adottato.

Dalla figura si vede che:
- molti degli utenti presenti in names.txt non fanno parte del dominio MYNETWORK;
- l'utente Giulio fa parte del dominio MYNETWORK e richiede preauthentication: per questo utente lo script non ha costruito un AS-REQ;
- l’utente Mario, appartenente al dominio MYNETWORK, non richiede preauthentication. Per lui è stato inviato un AS-REQ e in figura si vede la risposta del DC.
 
Analizziamo meglio la risposta del DC: "krb5asrep" indica che quanto segue è la parte crittografata di un AS-REP del protocollo Kerberos. "23" indica che il tipo di crittografia utilizzata è RC4-HMAC. Questo è interessante perché indica che GetNPUsers ha richiesto al DC che l'AS-REP venisse criptato utilizzando RC4, un algoritmo di crittografia più lento rispetto ad AES (algoritmo usato di default in kerberos). Grazie a questo, il cracking tool che useremo richiederà meno tempo per portare a termine il password cracking e quindi determinare la password dell'utente Mario. <br>
In quanto segue indicheremo, per compattezza di notazione, K_mario come la chiave dell'utente Mario.

Per eseguire il password cracking e determinare la password di Mario utilizziamo john the ripper (john). La stringa ottenuta in riposta dal DC verrà salvata in un file di testo, denominato hash.asrep1. Quindi verrà lanciato john, a cui passiamo:
- un file di testo contenente ipotetiche password, qui denominato pwdComunit.txt;
- krb5asrep: il formato con cui calcolare l’hash; dal hash si trova la chiave. 
il documento contente il AS-REP criptato, che abbiamo chiamato hash.asrep1
john prenderà le password contenute nel file pwdComuni, usando i parametri specificati, relativi al formato e al tipo di crittografia, calcola l’hash di ogni password, da questa ricava la chiave e vede se è corretta per l’AS-REP criptato che gli abbiamo fornito. 


&nbsp;

![The Markdown Mark](images/john.png)
_Figura 3: Esecuzione di john the ripper_

&nbsp;


Dalla figura si evince che l’esecuzione di john ha permesso di determinare che la password di Mario è “ciaoBelli!1”. Questo significa che questa password era presente nel file pwdComuni.txt che è stato passato al tool. 


Ne consegue che un attaccante che non conosceva la password di un utente ha ottenuto in risposta dal DC un messaggio criptato con la chiave di questo utente. L'attaccante dunque, montando un password cracking attack, può determinare la password di questo utente. 


&nbsp;

## Network Sniffing di AS-REQ + Password Cracking

### Contesto
Nell’ambito dell’autenticazione di un utente con il protocollo Kerberos, la workstation su cui un utente si vuole autenticare ed il nodo su cui è presente il domain controller si scambiano dei pacchetti volti a verificare se l’utente può essere autenticato su quella workstation. In particolare il primo messaggio inviato dalla workstation viene denominato AS-REQ, ovvero Authentication Service Request ed è criptato con la chiave dell’utente. 
L’obiettivo di questa parte di demo è intercettare l’AS-REQ di un utente inserito nel dominio mynetwork.local e montare un attacco di tipo password cracking per risalire alla password di tale utente. 

## Esecuzione dell’Attacco 
L’idea è quella di intercettare lo scambio di pacchetti fra il nodo su cui un utente si autenticherà e il nodo su cui è presente il DC. Per farlo occorre diventare Man In The Middle (MITM). Questo perché le macchine virtuali sono configurate per quanto riguarda la rete con “Internal Network”, quindi la rete viene gestita da uno “switch virtuale” e gli switch in generale utilizzano le tabelle di indirizzi MAC e lavorano inviando pacchetti solo alla porta che corrisponde all'indirizzo MAC del destinatario. Ne consegue che l’attaccante, restando all’esterno della comunicazione non riesce a vedere i pacchetti scambiati fra due nodi. Pertanto l’attaccante deve fare in modo che il traffico passi attraverso di lui. Ne deriva l’esigenza di diventare MITM. In questa demo l’attaccante diventerà MITM utilizzando ettercap, un tool di kali che permette di eseguire un ARP spoofing, quindi di diventare MITM a livello Ethernet. 
L’idea alla base del funzionamento di questo tool e dell’ARP spoofing è inviare messaggi ARP spoofed, cioè falsi, in modo che quando un nodo deve comunicare con il DC, l’attaccante ha associato il proprio indirizzo MAC all’indirizzo IP del nodo su cui è presente il DC quindi i pacchetti destinati a quest ultimo arrivano al nodo su cui sta l’attaccante; analogamente l’attaccante invia dei messaggi ARP spoofed per associare il proprio indirizzo MAC all’indirizzo IP del nodo su cui l’utente si sta autenticando, in modo che  quando il DC deve parlare con quel nodo,  il traffico passi attraverso l’attaccante.
È interessante osservare che qui torna utile l’ipotesi che l’attaccante conosca l’indirizzo IP del nodo su cui si trova il DC e il range degli indirizzi IP assegnati ai nodi dell’organizzazione. 

&nbsp;

![The Markdown Mark](images/ettercap.png)
_Figura 4: Esecuzione di ettercap_

&nbsp;


La figura rappresenta l’esecuzione di ettercap al fine di diventare MITM a livello Ethernet. Il presupposto è quello di conoscere l’indirizzo IP del nodo su cui sta il DC (qui 192.168.1.233) e di scegliere l’indirizzo IP di un nodo all’interno del range di indirizzi IP noti. L’attaccante intercetta il traffico fra questi due nodi e auspicabilmente un utente si collegherà al DC da quel nodo in particolare; se così non dovesse essere l’attaccante può scegliere un altro indirizzo IP e riprovare. 

In particolare è interessante osservare i veri indirizzi MAC delle due macchine.


&nbsp;

![The Markdown Mark](images/ARP.png)
_Figura 5: Pacchetti ARP_ 

&nbsp;

192.168.1.137 è l’indirizzo IP della macchina Windows 10;  
192.168.1.233 è l’indirizzo IP del nodo su cui è presente il domain controller. 
Questa figura illustra lo scambio di pacchetti ARP che ha permesso all’attaccante di associare il proprio indirizzo MAC (quello di kali, che è la macchina da cui l’attaccante opera) ai due nodi: ne consegue che qualunque messaggio indirizzato a 192.168.1.137 verrà inviato a kali; analogamente qualunque messaggio indirizzato a 192.168.1.233 arriverà a kali.

Ora l’attaccante è diventato MITM fra il nodo su cui sta il DC e un nodo in particolare dell’organizzazione (cioè 192.168.1.137 ). Supponiamo ora che, su quel nodo, ci sia un utente (con pre authentication) che esegue un interactive logon. L’attaccante riesce ad intercettare lo scambio di pacchetti fra la workstation e il DC. Per farlo utilizzeremo wireshark, l’interfaccia di rete che intercettiamo è eth0, filtriamo utilizzando il protocollo kerberos, che è quello a cui siamo interessati.

&nbsp;

![The Markdown Mark](images/wireshark.png)
_Figura 6: Wireshark_

&nbsp;


In particolare, il messaggio a cui siamo interessati è AS-REQ, che, come indicato dalla figura, è il pacchetto che la workstation invia alla macchina con il DC. L’obiettivo di questa parte di demo è fare un offline guessing attack per ricavare la password dell’utente, del quale abbiamo intercettato l’AS-REQ.

Analizzando più nel dettaglio l’AS-REQ, le informazioni rilevanti per montare l’attacco sono: 
etype: il tipo di crittografia utilizzata, qui 18
cipher: il valore criptato
CNameString: lo username dell’utente che ha inviato l’AS-REQ
realm: dominio di cui fa parte questo utente
questi sono tutti parametri che ci serviranno per costruire la stringa da passare a hashcat che è il tool che verrà utilizzato per eseguire il password cracking. 

&nbsp;

![The Markdown Mark](images/AS-REQ.png)
_Figura 7: AS-REQ nel dettaglio_ 

&nbsp;


Per costruire la stringa da passare a hashcat si possono consultare degli esempi online, in particolare il formato corretto è quello indicato in figura: 

&nbsp;

![The Markdown Mark](images/hashcat.png)
_Figura 8: Esecuzione di hashcat_ 

&nbsp;


dove:
krb5pa è il formato con cui calcolare l’hash. Dall’hash, in maniera deterministica, si risale alla chiave 
18 è il tipo di crittografia utilizzata per generare il valore “cipher”
tecnico2 è lo username dell’utente di cui abbiamo intercettato AS-REQ
MYNETWORK.LOCAL è il dominio di cui l’utente fa parte

hashcat si aspetta anche un file di testo contenente alcune password, qui indicato con pwdComuni.txt. Il tool, utilizzando i parametri specificati relativamente a formato e tipo di crittografia, calcola l’hash per ogni password presente nella lista, da questo calcola la chiave e vede se è corretta per il messaggio intercettato. Se l’operazione va a buon fine, cioè se la chiave di “tecnico2” è presente nell’elenco passato, hashcat restituisce la password dell’utente, come si evince dalla figura seguente. 


&nbsp;

![The Markdown Mark](images/resHashcat.png)
_Figura 7: Risultato dell'esecuzione di hashcat_ 

&nbsp;

