#import "template/pks.typ": pks

#show: pks.with(
  title: "Názov práce",
  subject: "Počítačové a komunikačné siete",
  author: "Meno Priezvisko",
  ais-id: "xxxxxx",
  supervisor: "Meno Priezvisko",
  class-time: "Deň xx:xx - xx:xx",
  font: "Liberation Serif", // Na windows je možné použiť aj "Times New Roman"
)
// Dokumentácia má byť stručná, prehľadná a bez zbytočnej vaty.
// Pri prvom odovzdaní spracujte časti požadované pre JSON PoC. Pri finálnom odovzdaní dokumentáciu doplňte o binárny formát, Lua dissector, výsledky merania a ďalšie požadované náležitosti.

// Nasledujúca štruktúra je odporúčaná. Kapitoly môžete premenovať, spojiť alebo usporiadať inak, ak dokumentácia obsahuje všetky povinné náležitosti zadania. Pred odovzdaním nahraďte túto osnovu skutočným obsahom dokumentácie.
= Úvod a architektúra riešenia

= Návrh protokolu

== Typy správ a ich formát

=== Príklad správy

= Implementácia servera a testovacieho programu

= Sekvenčné diagramy a overenie UAT

// Obrázky a diagramy musia byť čitateľné a bez zbytočných prvkov. Na obrázky odkazujte aj v texte (@fig-ukazka).
// rect(...) môžete nahradiť napríklad image("diagram.png", width: 100%).
#figure(
  rect(width: 100%, height: 45mm, fill: rgb("00ffff"), stroke: none),
  kind: image,
  caption: [Ukážkový obrázok - nahraďte vlastným diagramom.],
) <fig-ukazka>

= Meranie efektivity protokolu

= Zhodnotenie riešenia

= Príloha A

