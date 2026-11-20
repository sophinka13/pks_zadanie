POROVNANIE EFEKTIVITY – ANALYZA SERIALIZOVANYCH BAJTOV
====================================================

Toto je reprodukovatelna analyza skutocnych vystupov encoderov s vypoctom
nizsich vrstiev. Nie je to zachyt z beziazcich serverov ani meranie rychlosti,
latencie, energie alebo spolahlivosti fyzickej siete. PCAP subory su synteticke;
ich datum a casovy priebeh su modelove. Na finalne overenie este treba zivy
zachyt vlastnych programov na dvoch pocitacoch.

SPUSTENIE
  python3 measure_efficiency.py
  python3 measure_efficiency.py --samples 60 --seed 42 --out measurements

Python 3; graf vyzaduje matplotlib (pouzita verzia 3.11.2).
Vstupy sa pri rovnakom seed a samples vytvoria identicky a ulozia do inputs.json.
Parametre aj vsetky pakety su dostupne na kontrolu. Nemen vstupy medzi variantmi.

SCENAR A POROVNATELNOST
  4 senzory, kazdy 60 merani, logicky interval 10 s: 240 merani.
  Steady: 240 datovych sprav + 240 potvrdeni = 480 paketov.
  Registracia vlastnych protokolov: 4 REGISTER + 4 odpovede = 8 paketov navyse.
  Spolu vlastny zakladny scenar: 488 paketov. Graf porovnava iba steady.

  JSON pouziva encoder a CRC povodneho json_baseline/lib.py a povodne polia.
  Binary pouziva priamo aktualny encode_packet z binary_protocol.py.
  Seq a tokeny su deterministicke modelove hodnoty; nejde o presny zaznam
  pocitadiel konkretnych behov povodneho servera. Kazdy senzor ma vlastny token.
  Vstupy merania a ich poradie su pre vsetky varianty rovnake.

  CoAP-JSON: model standardneho UDP CoAP CON POST na /meteo/<ID>,
  8 B token, 4 B hlavicka, Uri-Path options, Content-Format application/json
  (50), payload marker a JSON obsahujuci vsetky hodnoty. Odpoved je
  piggyback ACK 2.04 Changed s rovnakym message ID a 8 B tokenom.
  CoAP-packed pouziva ten isty CoAP postup, ale Content-Format
  application/octet-stream (42) a nase vlastne bitovo zabalene hodnoty.
  Ide o citlivostnu analyzu efektu payloadu, nie o standardizovany format
  senzorovych dat CoAP. Server musi poznat schemu daneho resource.

  CoAP pakety sa vytvaraju lokalne podla RFC; nie je tu implementovany CoAP
  server, retransmisny stavovy automat ani zivy CoAP benchmark. Platnost
  struktury bola overena natívnym CoAP dissektorom v TShark 4.6.8.
  CoAP nema nase registracie, session token ani aplikacne CRC32. Jeho token
  služi na korelaciu poziadavky a odpovede, nie na autentifikaciu relacie.
  Porovnavame preto iba objem prenosu potvrdenych merani, nie rovnocennost
  vsetkych sluzieb. Ani jeden variant nezahrna TLS/DTLS/OSCORE.
  Nasa kratka binarna schema je specializovana, CoAP poskytuje standardne
  resource/response rozhranie a interoperabilitu; mensia velkost nie je dokaz,
  ze je vlastny protokol vseobecne lepsi.

UCETNICTVO VRSTIEV
  L7 = presna dlzka bajtov vytvorenych encoderom.
  L3 = L7 + 8 B UDP + 20 B IPv4 (bez options).
  Ethernet II = max(64, L3 + 14 B hlavicka + 4 B FCS), bez VLAN.
  Medium byte-times = Ethernet + 8 B preambula/SFD + 12 bajtovych casov IFG.
  IFG nie su prenesene datove bajty; preto je uvedeny oddelene.
  Nepocitame ARP, DNS, Wi-Fi overhead, IPv6, straty ani fragmentaciu.
  Model nepouziva kompresiu, batching ani retazenie viac merani do jedneho paketu.
  PCAP obsahuje Ethernet padding, ale nie FCS; pre porovnanie so stlpcom
  ethernet_bytes treba k frame.len pripocitat 4 B pre kazdy paket.
  UDP checksum je v syntetickom IPv4 zachyte nula (povolene); zive sockety
  sa spravaju podla OS. Tento zachyt nesluzi na test siete.

VYSLEDKY PRE DEFAULT (seed 42, 240 potvrdenych merani)
  Variant         L7 bajty    Ethernet bajty vratane FCS a paddingu
  JSON              47777            69857
  Binary             9300            31620
  CoAP-JSON         25135            48655
  CoAP-packed       10260            33780

  Binary oproti JSON setri priblizne 80.5 % na L7 a 54.7 % na Ethernete.
  Rozdiel sposobuje rezia nizsich vrstiev a minimalna dlzka ethernetoveho ramca.
  Registracie navyse stoja 535 B L7/903 B Ethernet pri JSON a
  156 B L7/528 B Ethernet pri Binary.

  Binary steady: 5220 B DATA + 4080 B ACK = 9300 B L7.
  Samotne zabalene hodnoty merani zaberaju 1140 B (vratane bitoveho paddingu).
  DATA hlavicky a CRC spolu 4080 B. Potvrdenia pridavaju dalsich 4080 B.
  Uzitocne zabalene hodnoty tak tvoria 12.26 % celeho potvrdeneho L7 prenosu;
  v samotnych DATA tvoria 21.84 %. Z toho vidno, ze dalsia optimalizacia
  hlaviciek a ACK by mala vacsi efekt ako setrenie poslednych bitov hodnot.
  CoAP-packed je blizsie k Binary nez CoAP-JSON: dolezity je aj format dat,
  nielen transportna hlavicka. Nevyvodzujeme z toho zivotnost baterie.

DALSIE ODDELENE SCENARE V summary.csv
  corruption: poskodena DATA, RETRANSMIT, spravna DATA, ACK (4 pakety).
  ack_loss: x=5; 3 pokusy prvej spravy, 3 pokusy druhej, 1 ACK (7 paketov).
  idle_responsive: 3 KEEPALIVE/KEEPALIVE_ACK dvojice (6 paketov).
  disconnected: 3 KEEPALIVE bez odpovede, zrusenie relacie pri 30 s (3 pakety).
  Su to modely poctov a dlzok; casovanie realne overuju tests/test_presentation.py.
  JSON baseline este neimplementuje UAT 5, jeho ack_loss je preto vypoctovy
  model toho isteho scenara, nie vystup jeho povodneho programu.

SUBORY
  inputs.json             spolocne hodnoty merani
  packets.csv             pocty bajtov kazdeho paketu a vrstva
  summary.csv             sucty podla variantu a scenara
  per_sensor.csv          priemerne bajty na potvrdene meranie kazdeho typu
  comparison.svg/.png     grafy steady; SVG je vhodne do dokumentacie
  *.pcap                  synteticke pakety otvoritelne vo Wiresharku

KONTROLA A CO ESTE NASLEDUJE
  python3 -m unittest discover -s tests -p test_efficiency.py -v
  Velkosti L7/L3/L2 steady boli nezavisle prepocitane cez TShark z PCAP.
  Binary steady sa dekoduje existujucim Lua dissektorom bez chyb CRC/formatu.
  CoAP steady nema chyby struktury ani neplanovane retransmisie.
  Pred finalnym odovzdanim treba doplnit zivy zachyt JSON a Binary na rovnakej
  ulozenej sade dat, overit realny pocet paketov a vysvetlit odchylky od modelu.
  Pre maximum bodov nemožno tento model vydavat za hotovy fyzicky benchmark.

ZDROJE
  CoAP: RFC 7252, casti 3, 4, 5 a 12.3:
    https://www.rfc-editor.org/rfc/rfc7252.html
  CoAP moze prenasat rozne reprezentacie senzorovych hodnot, napr. SenML;
  tento model SenML neimplementuje:
    https://www.rfc-editor.org/rfc/rfc8428.html

Skript, analyza a testy boli pripravene s pomocou AI.
