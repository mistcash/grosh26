#!/usr/bin/env python3
"""Build docs/polyring-toolkit.pdf from the site pages.

The book takes the <main> of the overview, guide and paper pages, wraps each in
a chapter opener, adds a cover and a contents page, then prints it with headless
Chrome. A second pass fills the contents page numbers in, and pypdf stamps the
folios and writes the PDF outline.

Requirements:
  * Chrome or Chromium (CHROME=/path/to/chrome to override)
  * poppler: pdftotext, pdfinfo
  * pypdf:  python3 -m pip install pypdf

Usage:
  python3 docs/book/build.py
"""

from __future__ import annotations

import html as htmlmod
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DOCS = HERE.parent
OUT = DOCS / "polyring-toolkit.pdf"
BOOK_HTML = HERE / "book.html"
BUILD_PDF = HERE / ".build.pdf"

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
    os.path.expanduser("~/Library/Caches/ms-playwright/chromium-1248/chrome-mac-arm64/Chromium.app/Contents/MacOS/Chromium"),
    os.path.expanduser("~/Library/Caches/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-mac-arm64/chrome-headless-shell"),
    os.path.expanduser("~/Library/Caches/ms-playwright/chromium_headless_shell-1248/chrome-headless-shell-linux64/chrome-headless-shell"),
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
]


# --------------------------------------------------------------------------- #
# source pages
# --------------------------------------------------------------------------- #

@dataclass
class Chapter:
    no: int
    title: str
    standfirst: str
    source: str
    body: str = ""
    sections: list[tuple[str, str]] = field(default_factory=list)  # (id, text)
    section_pages: dict[str, int] = field(default_factory=dict)
    page: int = 0


CHAPTERS = [
    Chapter(
        1,
        "Overview",
        "polyring is the Polynomial Ring Toolkit for gnark. Its first use is recursion: verify a "
        "Groth16 proof inside your circuit with up to 38% fewer constraints than gnark's own pairing.",
        "index.html",
    ),
    Chapter(
        2,
        "Guide",
        "Eight steps from an inner proof to a contract that verifies the recursive proof. All code "
        "comes from a module that runs the whole flow in about a minute.",
        "guide.html",
    ),
    Chapter(
        3,
        "Paper",
        "Pairing Proofs and Polynomial Ring Toolkit, to appear in IACR TCHES 2027. "
        "Shramee Srivastav, MIST.cash.",
        "paper.html",
    ),
]


def strip_between(text: str, start: str, end: str) -> str:
    """Remove from the first `start` match up to (not including) `end`."""
    return re.sub(start + r".*?(?=" + end + r")", "", text, flags=re.S)


def clean_main(main: str, chapter: Chapter) -> str:
    if chapter.no == 1:
        main = strip_between(main, r'<div class="hero">', r"<section class=\"band\"")
        main = re.sub(r'<section class="band tint" aria-label="Next">.*$', "", main, flags=re.S)
    else:
        main = strip_between(main, r'<div class="page-head">', r'<div class="wrap (?:guide|paper)">')
    if chapter.no == 2:
        main = re.sub(r'<nav class="toc".*?</nav>', "", main, flags=re.S)

    # interactive bits that make no sense on paper
    main = re.sub(r'<div class="btns"[^>]*>.*?</div>', "", main, flags=re.S)
    main = re.sub(r'<div class="toggle"[^>]*>.*?</div>', "", main, flags=re.S)
    main = re.sub(r'<button class="copy"[^>]*>.*?</button>', "", main, flags=re.S)
    main = re.sub(r'<button type="button">Copy</button>', "", main, flags=re.S)
    main = re.sub(r"<script\b.*?</script>", "", main, flags=re.S)
    return main.strip()


def rewrite_links(fragment: str, chapter: Chapter) -> str:
    """Point site links at the book's own chapters and keep ids unique."""
    targets = {"guide.html": 2, "paper.html": 3}

    def href(match: re.Match) -> str:
        raw = match.group(1)
        if raw.startswith(("http://", "https://", "mailto:")):
            return match.group(0)
        page, _, frag = raw.partition("#")
        if page in ("", "./", "index.html"):
            if not page and frag:
                return f'href="#ch{chapter.no}-{frag}"'
            if page == "":
                return match.group(0)
            return f'href="#ch1-{frag}"' if frag else 'href="#ch1"'
        target = targets.get(page)
        if target:
            return f'href="#ch{target}-{frag}"' if frag else f'href="#ch{target}"'
        return match.group(0)

    fragment = re.sub(r'href="([^"]+)"', href, fragment)

    def ident(match: re.Match) -> str:
        value = match.group(1)
        return f'id="ch{chapter.no}-{value}"'

    return re.sub(r'id="([^"]+)"', ident, fragment)


def add_heading_ids(fragment: str, chapter: Chapter) -> tuple[str, list[tuple[str, str]]]:
    """Give every h2 an id and collect (id, text) for the contents page."""
    sections: list[tuple[str, str]] = []
    counter = 0

    def add(match: re.Match) -> str:
        nonlocal counter
        attrs, inner = match.group(1), match.group(2)
        found = re.search(r'id="([^"]+)"', attrs)
        if found:
            ident = found.group(1)
        else:
            counter += 1
            ident = f"ch{chapter.no}-h{counter}"
            attrs = attrs + f' id="{ident}"'
        text = htmlmod.unescape(re.sub(r"<[^>]+>", "", inner))
        sections.append((ident, re.sub(r"\s+", " ", text).strip()))
        return f"<h2{attrs}>{inner}</h2>"

    fragment = re.sub(r"<h2([^>]*)>(.*?)</h2>", add, fragment, flags=re.S)
    return fragment, sections


# --------------------------------------------------------------------------- #
# html
# --------------------------------------------------------------------------- #

def wordmark_symbol() -> str:
    src = (DOCS / "assets" / "mist.cash.svg").read_text()
    src = re.sub(r"^<\?xml[^>]*\?>\s*", "", src)
    src = re.sub(r"^<!DOCTYPE[^>]*>\s*", "", src)
    inner = re.search(r"<svg\b[^>]*>(.*)</svg>\s*$", src, re.S).group(1).strip()
    return (
        '<svg width="0" height="0" style="position:absolute" aria-hidden="true" focusable="false">\n'
        '    <symbol id="mist-cash" viewBox="0 0 2013 337">\n'
        f"      {inner}\n"
        "    </symbol>\n"
        "  </svg>"
    )


def contents_html(chapters: list[Chapter], pages: dict[str, int] | None) -> str:
    def num(key: str) -> str:
        if pages is None:
            return "00"
        return str(pages.get(key, "–"))

    rows = ['<section class="contents">']
    rows.append('<span class="eyebrow">polyring toolkit</span>')
    rows.append("<h1>Contents</h1>")
    for chapter in chapters:
        rows.append(
            '<div class="toc-chapter">'
            f'<span class="no">{chapter.no:02d}</span>'
            f'<span class="t">{chapter.title}</span>'
            f'<span class="p">{num(f"ch{chapter.no}")}</span>'
            "</div>"
        )
        for ident, text in chapter.sections:
            rows.append(
                '<div class="toc-sec">'
                f"<span>{htmlmod.escape(text)}</span>"
                '<span class="dots"></span>'
                f'<span class="p">{num(ident)}</span>'
                "</div>"
            )
    rows.append("</section>")
    return "\n".join(rows)


def opener_html(chapter: Chapter) -> str:
    items = "".join(
        f"<li>{htmlmod.escape(text)}</li>" for _, text in chapter.sections
    )
    return f"""
<section class="opener">
  <span class="eyebrow">Chapter {chapter.no:02d}</span>
  <div class="no">{chapter.no:02d}</div>
  <h1>{htmlmod.escape(chapter.title)}</h1>
  <p class="standfirst">{htmlmod.escape(chapter.standfirst)}</p>
  <div class="opener-rule"></div>
  <div class="opener-toc">
    <span class="eyebrow">In this chapter</span>
    <ul>{items}</ul>
  </div>
</section>
"""


def cover_html() -> str:
    return """
<section class="cover">
  <svg class="brand" viewBox="0 0 2013 337" aria-label="MIST.cash"><use href="#mist-cash"/></svg>
  <div class="spacer"></div>
  <span class="kicker">Documentation · Guide · Paper</span>
  <h1>polyring<br>toolkit</h1>
  <p class="sub">Fast polynomial ring multiplications in gnark. Verify a Groth16 proof inside your
    circuit with up to 38% fewer constraints.</p>
  <div class="rule"></div>
  <div class="meta">
    <span>polyring.mist.cash</span>
    <span>v0.1 · IACR TCHES 2027</span>
  </div>
</section>
"""


COLOPHON = """
<section class="colophon">
  <span class="eyebrow">Colophon</span>
  <h2>polyring toolkit</h2>
  <p>This book collects the polyring website: the overview, the step-by-step guide, and the paper
    summary. The library is Apache-2.0 licensed. Version 0.1 is unaudited; use it for research and
    on testnets.</p>
  <dl>
    <dt>Source</dt><dd>github.com/mistcash/polyring</dd>
    <dt>Website</dt><dd>polyring.mist.cash</dd>
    <dt>Paper</dt><dd>IACR TCHES 2027 · polyring.mist.cash/paper.pdf</dd>
    <dt>Author</dt><dd>Shramee Srivastav, MIST.cash</dd>
    <dt>Type</dt><dd>Josefin Sans and Sen, set in the MIST design system</dd>
  </dl>
</section>
"""


def build_html(chapters: list[Chapter], pages: dict[str, int] | None) -> str:
    parts = [
        '<!doctype html>',
        '<html lang="en" data-theme="light">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="robots" content="noindex">',
        "<title>polyring toolkit — documentation</title>",
        '<link rel="preconnect" href="https://fonts.googleapis.com">',
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>',
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Josefin+Sans:wght@600;700&family=Sen:wght@400;600;700;800&display=swap">',
        '<link rel="stylesheet" href="../assets/site.css">',
        '<link rel="stylesheet" href="book.css">',
        "</head>",
        "<body>",
        wordmark_symbol(),
        cover_html(),
        contents_html(chapters, pages),
    ]
    for chapter in chapters:
        parts.append(opener_html(chapter))
        parts.append(f'<div class="chapter-body">\n{chapter.body}\n</div>')
    parts.append(COLOPHON)
    parts.append("</body></html>")
    return "\n".join(parts)


# --------------------------------------------------------------------------- #
# tooling
# --------------------------------------------------------------------------- #

def find_chrome() -> str:
    env = os.environ.get("CHROME")
    if env:
        return env
    for candidate in CHROME_CANDIDATES:
        if os.path.isabs(candidate):
            if os.access(candidate, os.X_OK):
                return candidate
        elif shutil.which(candidate):
            return shutil.which(candidate)
    sys.exit("No Chrome or Chromium found. Set CHROME=/path/to/chrome.")


def render(chrome: str, out: Path) -> None:
    subprocess.run(
        [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--virtual-time-budget=12000",
            f"--print-to-pdf={out}",
            BOOK_HTML.as_uri(),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def page_count(pdf: Path) -> int:
    info = subprocess.run(["pdfinfo", str(pdf)], check=True, capture_output=True, text=True).stdout
    return int(re.search(r"^Pages:\s+(\d+)", info, re.M).group(1))


def page_text(pdf: Path, page: int) -> str:
    out = subprocess.run(
        ["pdftotext", "-f", str(page), "-l", str(page), "-layout", str(pdf), "-"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return re.sub(r"\s+", " ", out).strip()


def squash(text: str) -> str:
    return re.sub(r"\s+", "", text).lower()


def find_pages(pdf: Path, chapters: list[Chapter]) -> dict[str, int]:
    total = page_count(pdf)
    texts = {p: page_text(pdf, p) for p in range(1, total + 1)}
    pages: dict[str, int] = {}
    for chapter in chapters:
        marker = squash(f"Chapter {chapter.no:02d}")
        found = next((p for p in sorted(texts) if p > 2 and marker in squash(texts[p])), 0)
        if not found:
            found = next((p for p in sorted(texts) if p > 2 and chapter.title in texts[p]), 0)
        chapter.page = found
        pages[f"ch{chapter.no}"] = found
        for ident, text in chapter.sections:
            needle = squash(text)
            page = next(
                (p for p in sorted(texts) if p > found and needle and needle in squash(texts[p])),
                0,
            )
            page = page or found
            pages[ident] = page
            chapter.section_pages[ident] = page
    return pages


def stamp_folios(pdf: Path, chrome: str, out: Path) -> list[int]:
    """Overlay folios on every page except the cover."""
    total = page_count(pdf)
    rows = []
    for page in range(2, total + 1):
        rows.append(
            '<div class="folio"><span>polyring toolkit</span>'
            f"<span>{page}</span></div>"
        )
    doc = f"""<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Sen:wght@400;600&display=swap">
<style>
  @page {{ size: A4; margin: 0; }}
  html, body {{ margin: 0; background: transparent; }}
  .folio {{ position: relative; width: 210mm; height: 297mm; page-break-after: always;
            font: 500 8pt/1 "IBM Plex Mono", monospace; color: #5a6b7c; }}
  .folio:last-child {{ page-break-after: auto; }}
  .folio span:first-child {{ position: absolute; left: 18mm; bottom: 11mm; }}
  .folio span:last-child {{ position: absolute; right: 18mm; bottom: 11mm; font-size: 8.5pt; color: #33414f; }}
</style></head><body>
{''.join(rows)}
</body></html>"""
    overlay_html = BUILD_PDF.with_name(".folios.html")
    overlay_pdf = BUILD_PDF.with_name(".folios.pdf")
    overlay_html.write_text(doc)
    subprocess.run(
        [
            chrome,
            "--headless",
            "--disable-gpu",
            "--no-pdf-header-footer",
            "--virtual-time-budget=6000",
            f"--print-to-pdf={overlay_pdf}",
            overlay_html.as_uri(),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return total


def finish(pdf: Path, out: Path, chapters: list[Chapter], chrome: str) -> None:
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        print("pypdf is missing: writing the PDF without folios or bookmarks.")
        shutil.copy(pdf, out)
        return

    overlay_pdf = BUILD_PDF.with_name(".folios.pdf")
    total = page_count(pdf)

    writer = PdfWriter()
    writer.append(str(pdf))

    if overlay_pdf.exists():
        folios = PdfReader(str(overlay_pdf))
        for index in range(1, min(total, len(folios.pages) + 1)):
            writer.pages[index].merge_page(folios.pages[index - 1])

    writer.add_outline_item("Cover", 0)
    writer.add_outline_item("Contents", 1)
    for chapter in chapters:
        parent = writer.add_outline_item(
            f"{chapter.no:02d}  {chapter.title}", max(chapter.page - 1, 0)
        )
        for ident, text in chapter.sections:
            page = chapter.section_pages.get(ident, chapter.page)
            writer.add_outline_item(text, max(page - 1, 0), parent=parent)

    writer.add_metadata(
        {
            "/Title": "polyring toolkit — documentation",
            "/Author": "Shramee Srivastav, MIST.cash",
            "/Subject": "Fast polynomial ring multiplications in gnark; Groth16 recursion",
            "/Keywords": "polyring, gnark, Groth16, pairing, recursion, BN254, BLS12-381",
            "/Creator": "polyring book builder",
            "/Producer": "headless Chrome + pypdf",
        }
    )
    with out.open("wb") as handle:
        writer.write(handle)


# --------------------------------------------------------------------------- #

def main() -> None:
    chrome = find_chrome()

    for chapter in CHAPTERS:
        page = (DOCS / chapter.source).read_text()
        main_html = re.search(r'<main id="main">(.*)</main>', page, re.S).group(1)
        fragment = clean_main(main_html, chapter)
        fragment = rewrite_links(fragment, chapter)
        fragment, chapter.sections = add_heading_ids(fragment, chapter)
        chapter.body = fragment

    # pass 1: lay the book out, learn where things land
    BOOK_HTML.write_text(build_html(CHAPTERS, None))
    render(chrome, BUILD_PDF)
    pages = find_pages(BUILD_PDF, CHAPTERS)

    # pass 2: same layout, real folios in the contents
    BOOK_HTML.write_text(build_html(CHAPTERS, pages))
    render(chrome, BUILD_PDF)

    stamp_folios(BUILD_PDF, chrome, BOOK_HTML.with_name(".folios.html"))
    finish(BUILD_PDF, OUT, CHAPTERS, chrome)

    # leave only the generated book.html behind
    for leftover in (".build.pdf", ".folios.pdf", ".folios.html"):
        (HERE / leftover).unlink(missing_ok=True)

    missing = [k for k, v in pages.items() if not v]
    print(f"wrote {OUT.relative_to(DOCS.parent)} · {page_count(OUT)} pages")
    if missing:
        print("could not place:", ", ".join(missing))


if __name__ == "__main__":
    main()
