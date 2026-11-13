# FIIT Meteo: navrh binarneho protokolu v1

Tento dokument je specifikacia pre dalsiu implementaciu. Aktualny kod stale
prenasa JSON. Navrh pouziva UDP, jednu spravu na datagram a network byte order
(big-endian). Logy zostanu citatelne objekty s nazvami parametrov.

## Spolocny format

| Pole | Velkost | Vyznam |
|---|---:|---|
| riadiaci bajt | 8 bitov | verzia: 2 bity, typ spravy: 3 bity, typ senzora: 2 bity, rezerva: 1 bit |
| seq | 32 bitov | poradove cislo poziadavky; odpoved opakuje toto cislo |
| token | 64 bitov | serverom pridelena relacia; pri REGISTER a odmietnuti registracie nula |
| payload | premenliva | podla typu spravy a senzora |
| crc | 32 bitov | CRC32 vsetkych predchadzajucich bajtov datagramu |

Pevna rezia je 17 bajtov. Riadiaci bajt od najvyssieho bitu:
`VV TTT SS R`. Verzia je `01`, rezervny bit je `0`.
Senzory: `00` ThermoNode, `01` WindSense, `10` RainDetect, `11` AirQuality.

Token ostava 64-bitovy ako v aktualnom kode. Server zabezpeci jedinecnost
aktivnych tokenov a nepouzije nulu. ID sa posiela iba pri registracii;
neskor server urci ID zo spojenia typu senzora, tokenu a adresy odosielatela.
Rozne senzory rovnakeho typu maju vlastne ID, tokeny a nezavisle stavy.
CRC je kontrola nahodneho poskodenia, nie kryptograficke overenie odosielatela.

## Typy sprav

| Kod | Sprava | Payload | Celkova dlzka |
|---|---|---|---:|
| 000 | REGISTER | dlzka ID: uint8, potom ID v UTF-8 | 18 + N B |
| 001 | ACK | ziadny | 17 B |
| 010 | REJECT | kod dovodu: uint8 | 18 B |
| 011 | DATA | bitovo zabalene hodnoty | 21 az 23 B |
| 100 | RETRANSMIT | ziadny | 17 B |
| 101 | KEEPALIVE | ziadny | 17 B |
| 110 | KEEPALIVE_ACK | ziadny | 17 B |
| 111 | REGISTER_ACK | ziadny; novy token je v hlavicke | 17 B |

ID ma 1 az 255 UTF-8 bajtov, nesmie byt prazdne ani tvorene iba medzerami.
REGISTER_ACK je oddeleny od datoveho ACK, aby sa nedala zamenit registracia
s potvrdenim merania. REJECT pouzije znamy token relacie; ak relacia nie je
platna alebo ide o registraciu, token je nula.

Kody REJECT: 1 neplatna relacia/token, 2 duplicitne ID, 3 neplatne hodnoty,
4 nepodporovana sprava alebo verzia, 5 konflikt poradoveho cisla,
6 nespravna adresa. Podrobny text zostava lokalne v logu.

Odpovede ACK, REGISTER_ACK, REJECT, RETRANSMIT a KEEPALIVE_ACK
opakuju seq prislusnej poziadavky; neposielaju samostatne ack_for.
Tester a server maju vlastne pocitadla poziadaviek. Odpoved sa priradi
podla relacie, ocakavaneho typu a seq; registracna odpoved aj podla adresy.
Pocitadla zacinaju od 1. Pred vycerpanim uint32 sa relacia musi obnovit;
seq sa v tej istej relacii znovu nepouzije. Pri obnove sa senzor najprv
odpoji a pocka na zrusenie starej relacie serverom.

## Kodovanie hodnot DATA

Pouzijeme cele nezaporne cislo:

`kod = (hodnota - minimum) * 10**pocet_desatinnych_miest`

Pocitame presne cez Decimal; neplatnu presnost odmietneme, nezaokruhlime ju.
Dekodovanie: `hodnota = minimum + kod / 10**pocet_desatinnych_miest`.
Priklad: teplota 21.3 sa pri minime -50.0 zakoduje ako 713.

| Senzor | Parameter | Rozsah kodu | Bitov |
|---|---|---:|---:|
| ThermoNode | temperature | 0..1100 | 11 |
| | humidity | 0..1000 | 10 |
| | dew_point | 0..1100 | 11 |
| | pressure | 0..30000 | 15 |
| WindSense | wind_speed | 0..500 | 9 |
| | wind_gust | 0..700 | 10 |
| | wind_direction | 0..359 | 9 |
| | turbulence | 0..10 | 4 |
| RainDetect | rainfall | 0..5000 | 13 |
| | soil_moisture | 0..1000 | 10 |
| | flood_risk | 0..3 | 2 |
| | rain_duration | 0..60 | 6 |
| AirQuality | co2 | 0..4700 | 13 |
| | ozone | 0..5000 | 13 |
| | air_quality_index | 0..500 | 9 |

Polia su v uvedenom poradi, balene od najvyssich bitov.
Na konci payloadu doplnime nuly do celeho bajtu.

| Senzor | Datove bity | Doplnkove nuly | Payload | Cela DATA |
|---|---:|---:|---:|---:|
| ThermoNode | 47 | 1 | 6 B | 23 B |
| WindSense | 32 | 0 | 4 B | 21 B |
| RainDetect | 31 | 1 | 4 B | 21 B |
| AirQuality | 35 | 5 | 5 B | 22 B |

Minimalny pocet bitov kazdeho parametra je bit_length maximalneho kodu.
Neprenasame nazvy poli, desatinne bodky ani opakovane textove ID.
Nevkladame timestamp, pretoze aktualne poziadavky nevyzaduju cas merania
v prenose; cas logovania je lokalny UTC cas programu.

## Integrita, chyby a opakovanie

CRC32 pouzije zlib.crc32, vysledok ako 4 bajty big-endian. Pokryva aj hlavicku.
Pri simulacii chyby tester zmeni bit payloadu az po vypocte CRC a uchova original.
Pri chybnom CRC server nesmie pouzit hlavicku ako doveryhodnu. RETRANSMIT
posle len ak sa da poziadavka priradit existujucej relacii a jej adrese;
inak paket zahodi. Pri strate retransmisnej poziadavky pomoze casovac ACK.

Pri chybajucom ACK sa posle identicka DATA po 3 sekundach, najviac 3 odoslania
spolu. Po dalsich 3 sekundach bez ACK sa zahodi. Aj opakovania vyziadane
RETRANSMIT sa pocitaju do tohto limitu. Duplicitne platne DATA server znovu
potvrdi, ale nezapise ako nove meranie.

Dekoder kontroluje dlzku, verziu, rezervny bit, CRC, rozsahy kodov,
nulove doplnenie a platnost UTF-8. Nadbytocne bajty nie su povolene.
Odpoved na neplatny datagram sa posiela iba ak je bezpecne priraditelny;
inak sa chyba zaloguje a paket zahodi bez padu programu.

Casovanie KEEPALIVE ostava 15 s bez dat, potom sondy po 5 s a zrusenie
relacie po troch nezodpovedanych sondach a poslednom 5 s cakani.
Pri implementacii treba vyriesit aj klientsky 30 s casovac zo zadania:
doslovne pocitanie len od KEEPALIVE koliduje s beznou prevadzkou,
ked pri pravidelnych datach server sondy vobec neposiela. Toto spravanie
treba vyjasnit s cviciacim pred finalnym overenim.

## Co overime v dalsom kroku

- zakodovanie a dekodovanie kazdej spravy a hranic vsetkych parametrov;
- presne dlzky DATA 23/21/21/22 bajtov;
- odmietnutie neplatnych kodov, skratenych dat a chybneho CRC;
- rozdielne tokeny pre senzory rovnakeho typu;
- identicke bajty pri opakovani a spravne priradenie odpovedi;
- Lua dissector pouzije rovnake poradie bitov a poli.

JSON verziu zachovame na neskorsie porovnanie pri rovnakych vstupoch.
Uvedene velkosti su velkosti aplikacnych dat; meranie navyse zahrnie UDP,
IP a L2. Tento navrh sam o sebe nie je dokaz maximalneho bodoveho hodnotenia.

Tento navrh bol pripraveny s pomocou AI.
