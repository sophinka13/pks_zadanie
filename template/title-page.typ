#let title-page(title: none, subject: none, author: none, ais-id: none, supervisor: none, class-time: none) = page(
  paper: "a4",
  margin: (left: 25mm, right: 25mm, top: 18mm, bottom: 12mm),
  header: none,
  footer: none,
  numbering: none,
)[
  #set par(justify: false, leading: 2pt, spacing: 0pt)

  #align(center)[
    #text(size: 18pt, weight: "bold")[Slovenská Technická Univerzita v Bratislave]
    #linebreak()
    #text(size: 14pt)[Fakulta informatiky a informačných technológií]
  ]

  #v(89mm)

  #align(center)[
    #text(size: 18pt, weight: "bold", title)
    #linebreak()
    #text(size: 14pt, subject)
    #v(7mm)
    #text(size: 14pt, weight: "bold", author)
    #linebreak()
    #text(size: 12pt)[AIS ID: #ais-id]
  ]

  #v(1fr)

  *Vedúci cvičenia:* #supervisor \
  *Čas cvičenia:* #class-time
]
