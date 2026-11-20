# pks_zadanie

Aktualny server a tester komunikuju binarnym protokolom v1 nad UDP.

```sh
python3 server.py
python3 tester.py
```

Logy sa vzdy zapisuju do suboru; volitelny vypis aj do terminalu:

```sh
python3 server.py --console-logs
python3 tester.py --console-logs
```

Dva nezavisle senzory kazdeho typu (8 celkovo, ID T-01, T-02 atd.):

```sh
python3 tester.py --sensors-per-type 2 --console-logs
```

Volba `--help` zobrazi dostupne argumenty. Pocet senzorov musi byt kladny.

Kazdy prikaz spusti v samostatnom terminali. IP a port nastav v programe.
Potrebny je Python 3 a subory `lib.py`, `binary_protocol.py`, `wire_protocol.py`.
Po zmene z JSON restartuj oba programy. Logy zostavaju citatelne v anglictine.

- Specifikacia: [NAVRH_BINARNEHO_PROTOKOLU.md](NAVRH_BINARNEHO_PROTOKOLU.md)
- Osobny navod: [NAVOD_PRE_MNA.txt](NAVOD_PRE_MNA.txt)
- Povodna spustitelna JSON verzia: `json_baseline/`
- Existujuce PDF dokumentacie a ZIP este opisuju povodnu verziu.
- UAT 5: serverove menu `1`, ID senzora a pocet vynechanych ACK (0 = zrusit).
  Tester opakuje po 3 s, maximalne 3 odoslania; potom spravu zahodi.
- Lua dissector: [lua/README.md](lua/README.md), port 9000 alebo Decode As.
- Analyza efektivity: `python3 measure_efficiency.py`; vysledky a metodika
  v [measurements/README.txt](measurements/README.txt). Ide o serializacnu
  analyzu so syntetickymi PCAP, zivy zachyt este treba doplnit.

Testy bez siete:

```sh
python3 -m unittest discover -s tests -v
```

Aj lokalne UDP scenare UAT 1 az 5 (priblizne 80 sekund):

```sh
PKS_RUN_UDP_TESTS=1 python3 -m unittest discover -s tests -v
```

Binarne moduly a suvisiace upravy boli pripravene s pomocou AI.

Poznamka k casovacu: tester ukonci relaciu po 30 s bez platnej odpovede
servera (KEEPALIVE, ACK alebo RETRANSMIT). Zadanie uvadza iba posledny
KEEPALIVE, ale server pri pravidelnych datach sondy neposiela. Doslovny
vyklad by odpojil aj funkcny senzor. Tento rozdiel treba vyjasnit s cviciacim;
implementacia zatial zachovava kontrolu posledneho platneho kontaktu.
