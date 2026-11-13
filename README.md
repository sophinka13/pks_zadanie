# pks_zadanie

Aktualny server a tester komunikuju binarnym protokolom v1 nad UDP.

```sh
python3 server.py
python3 tester.py
```

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
- Meranie efektivity bude nasledovat.

Testy bez siete:

```sh
python3 -m unittest discover -s tests -v
```

Aj lokalne UDP scenare UAT 1 az 5 (priblizne 80 sekund):

```sh
PKS_RUN_UDP_TESTS=1 python3 -m unittest discover -s tests -v
```

Binarne moduly a suvisiace upravy boli pripravene s pomocou AI.
