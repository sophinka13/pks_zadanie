## Rychle pouzitie aktualnej verzie

1. Skopiruj aktualny `fiit_meteo.lua` do Personal Lua Plugins na pocitaci,
   kde bezi Wireshark, a **uplne restartuj Wireshark**. Na tomto Macu uz bola
   nainstalovana kopia aktualizovana. Na druhom pocitaci ju treba nahradit tiez.
2. Hodnoty DATA su teraz priamo v stlpci **Info**, napr.
   `DATA ThermoNode #2 | temperature=21.3 °C, humidity=55.4 %, ...`.
   V detailoch rozbal **FIIT Meteo v1 → Payload** pre jednotlive filtrovatelne polia.
3. Zapni **View → Colorize Packet List**, potom vyber
   **Tools → FIIT Meteo → Color packets by sensor**.
   Toto nastavi docasne farebne pravidla pre aktualnu relaciu Wiresharku
   (nahradi jeho 10 docasnych farebnych slotov).
4. Pre trvale farby pouzi **View → Coloring Rules → Import** a vyber
   `fiit_meteo_colors.txt`. Pravidla FIIT presun nad vseobecne UDP pravidla
   a potvrd **OK**. Subor s farbami sa nekopiruje do Lua Plugins.

Predvolene farby: ThermoNode modra, WindSense tyrkysova, RainDetect azurova,
AirQuality zelena; registracie zlta, ACK siva, KEEPALIVE olivova,
RETRANSMIT fialova a chyba CRC cervena. Su to farby celych riadkov paketov,
nie samostatne farby textu jednotlivych hodnot v detailovom strome.
Docasne farby zavisia od farebnej palety profilu; importovany subor obsahuje
konkretne farby. Chyby maju prednost pred farbou senzora.

Na inom porte sa platne binarne spravy rozpoznavaju aj heuristicky podla
hlavicky, presnej dlzky a CRC. Pre spolahlive zobrazenie poskodenych paketov
stale nastav port alebo pouzi **Decode As → FIITMETEO**.
Ak vidis iba UDP a surove Data, skontroluj nacitanie pluginu a Decode As.
Ak vidis chybu dvojitej registracie protokolu, odstran dalsie stare kopie pluginu.
Aktualna verzia osetruje dvojite nacitanie cez plugin a `-X lua_script`.

Farbenie pouziva oficialne Wireshark
[Lua GUI API](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Gui.html);
import vysvetluje [Wireshark Coloring Rules](https://wiki.wireshark.org/ColoringRules).
Upravy a testy boli pripravene s pomocou AI.

---

# Wireshark dissector FIIT Meteo v1

`fiit_meteo.lua` dekoduje vsetkych osem typov binarnych sprav, vsetky styri
senzory a ich hodnoty v povodnych jednotkach. Token cita ako 64-bitove cislo
bez straty presnosti. Overuje CRC32, dlzky, verziu, rezervny bit, seq,
platnost tokenu pre typ spravy, rozsahy hodnot, doplnkove bity a registracne ID.
CRC nie je overenie autenticity; pri chybnom CRC su zobrazene polia nedoveryhodne.
ID je priamo v pakete iba pri REGISTER; ostatne pakety identifikuje token.
Skript nevedie stav relacii, nekontroluje casovanie ani neoznacuje duplicity automaticky.

## Nacitanie na macOS

1. Vo Wiresharku otvor **About Wireshark → Folders** (v menu Wireshark).
2. Otvor priecinok **Personal Lua Plugins** (podla verzie moze byt uvedeny
   ako Personal Plugins). Ak neexistuje, vytvor ho.
3. Skopiruj do neho **iba `fiit_meteo.lua`**, potom restartuj Wireshark.
4. Pri otvoreni paketu na UDP porte 9000 uvidis protokol **FIITMETEO**.

Alternativa bez instalacie je spustenie z terminalu v koreni projektu:

```sh
/Applications/Wireshark.app/Contents/MacOS/Wireshark -X "lua_script:$PWD/lua/fiit_meteo.lua"
```

Pouzi iba jeden sposob nacitania, aby sa skript nenacital dvakrat.
Ak menu alebo umiestnenie priecinkov vyzera inak, autoritativnu cestu zobrazi:

```sh
/Applications/Wireshark.app/Contents/MacOS/tshark -G folders
```

Predvoleny serverovy port je **9000**. Pri inom porte ho nastav vo Wiresharku
v **Preferences → Protocols → FIIT Meteo v1 → UDP server port** alebo klikni
na UDP paket pravym tlacidlom, vyber **Decode As…** a protokol **FIITMETEO**.
Zvol port servera, nie docasne porty jednotlivych senzorov.

## Zachytavanie a filtre

Na jednom pocitaci s adresou 127.0.0.1 zachytavaj na **lo0 / Loopback**.
Medzi dvomi pocitacmi zachytavaj na aktivnom Ethernet/Wi-Fi rozhrani a testeru
zadaj skutocnu IP servera. Zachytavanie spusti pred registraciou.

Capture filter pri porte 9000: `udp port 9000`.
Display filtre po nacitani dissektora:

| Co zobrazit | Display filter |
|---|---|
| Vsetky spravy | `fiitmeteo` |
| Registracie a ich potvrdenia | `fiitmeteo.type == 0 || fiitmeteo.type == 7` |
| Merania | `fiitmeteo.type == 3` |
| ThermoNode | `fiitmeteo.sensor == 0` |
| Chybne CRC | `fiitmeteo.crc_ok == 0` |
| Chybna struktura | `fiitmeteo.malformed` |
| Vyziadanie opravy | `fiitmeteo.type == 4` |
| KEEPALIVE a odpovede | `fiitmeteo.type == 5 || fiitmeteo.type == 6` |
| DATA a ACK pre UAT 5 | `fiitmeteo.type == 3 || fiitmeteo.type == 1` |
| Konkretne poradove cislo | `fiitmeteo.seq == 2` |
| Vyssia teplota | `fiitmeteo.temperature > 20` |

Pre jednu relaciu skombinuj filter s tokenom z hlavicky, napriklad:
`fiitmeteo.token == 0x1234567890abcdef`.
Samotne seq nie je globalne jedinecne; rozne senzory mozu mat rovnake cislo.
Pri UAT 5 ma opakovanie rovnaky token, seq, hodnoty aj CRC.
Rozostupy zisti zo stlpca Time alebo pridaj stlpec `frame.time_delta_displayed`
po obmedzeni filtra na jednu relaciu a DATA. ACK bez CRC chyby potvrdzuje meranie;
chybajuce ACK a pocet opakovani vyhodnot podla zachyteneho priebehu.

## Overenie cez TShark

```sh
/Applications/Wireshark.app/Contents/MacOS/tshark \
  -X "lua_script:$PWD/lua/fiit_meteo.lua" -r zaznam.pcapng -Y fiitmeteo -V
```

Automaticke testy pouzivaju synteticke Ethernet/IPv4/UDP zachyty a porovnavaju
vysledky skutocneho TSharku s Python encoderom. Nevyzaduju otvorenie sietoveho
portu ani instalaciu pluginu. Ak TShark nie je nainstalovany, preskocia sa.

```sh
python3 -m unittest discover -s tests -p test_dissector.py -v
```

Overene s Wireshark/TShark 4.6.8. Testy nenahradzaju prezentaciu na dvoch
fyzickych zariadeniach. Implementacia aj testy boli pripravene s pomocou AI.

API: [Wireshark Lua Protocols and Dissectors](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Proto.html)
a [Dissection Tree](https://www.wireshark.org/docs/wsdg_html_chunked/lua_module_Tree.html).
