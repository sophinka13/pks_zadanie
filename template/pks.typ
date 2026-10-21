#import "title-page.typ": title-page

#let pks(
  title: "Názov práce",
  subject: "Počítačové a komunikačné siete",
  author: "Meno Priezvisko",
  ais-id: "xxxxxx",
  supervisor: "Meno Priezvisko",
  class-time: "Deň xx:xx - xx:xx",
  font: "Liberation Serif",
  body,
) = {
  set document(title: title, author: author)
  set text(font: font, size: 12pt, lang: "sk", top-edge: 0.8em, bottom-edge: -0.2em)
  set par(justify: true, first-line-indent: 0pt, leading: 0.5em, spacing: 12pt)
  set heading(numbering: none)

  show heading: it => {
    let sizes = (18pt, 16pt, 14pt)
    let before = (18pt, 14pt, 12pt)
    let after = (10pt, 8pt, 6pt)
    let index = calc.min(it.level, 3) - 1
    block(above: before.at(index), below: after.at(index), sticky: true)[
      #set par(justify: false, leading: 0.2em)
      #text(size: sizes.at(index), weight: "regular", it.body)
    ]
  }

  set figure(gap: 8pt)
  show figure.where(kind: image): set figure(supplement: [Obrázok])
  show figure.caption: set text(size: 11pt)
  show figure.caption: set par(justify: false, leading: 2pt)

  title-page(title: title, subject: subject, author: author, ais-id: ais-id, supervisor: supervisor, class-time: class-time)

  set page(
    paper: "a4",
    margin: (left: 25mm, right: 25mm, top: 32mm, bottom: 22mm),
    header-ascent: 9mm,
    footer-descent: 10mm,
    numbering: "1",
    number-align: center + bottom,
    header: [
      #set par(justify: false, leading: 2pt, spacing: 0pt)
      #grid(
        columns: (1fr, auto),
        column-gutter: 8mm,
        align: (left + top, right + top),
        [#subject \ FIIT\@STU \ #author],
        image("assets/logo.png", width: 27mm, alt: "Logo STU FIIT"),
      )
    ],
  )
  counter(page).update(1)

  outline(title: [Obsah], depth: 3, indent: 1.2em)
  pagebreak()

  body
}
