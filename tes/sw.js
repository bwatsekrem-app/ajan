// Service worker kopi TÈS la: kòd tès la nan app/ (separe ak prodiksyon), pwòp cache pa l.
self.GRANDON_SW = { baz: "app/", lokal: ["./", "index.html", "config.js", "manifest.webmanifest"], non: "tes",
  plis: ["../mak.css", "../logo-blan.png", "../ikon-blan.png", "../logo-koule.png", "../ikon-koule.png"] };
importScripts("app/sw.js");
