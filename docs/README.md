# Documentation

This directory is the project's documentation site.

- `index.html` — the homepage.
- `getting-started.md` — install, run the example, write your own, go on-chain.
- `how-it-works.md` — what the circuit does and why.
- `benchmarks.md` — the numbers, and how to reproduce them.
- `architecture.md` — the packages and the seams between them.

The markdown files are also readable on GitHub, at
<https://github.com/mistcash/polyring/tree/main/docs>.

`docs/agents/` is not part of the site: it holds the instructions the
repository's agents follow, and the Pages workflow leaves it out.

## Publishing

The site is plain static HTML and CSS — no build step, no Jekyll, no
dependencies. To publish it with GitHub Pages, either:

- set **Settings → Pages → Source** to **Deploy from a branch**, branch
  `main`, folder `/docs`; or
- let `.github/workflows/pages.yml` do it, which publishes `docs/` on every
  push to `main`.

Either way the site lands at <https://mistcash.github.io/polyring/>.

## Adding a page

Drop a `.md` file in and link it from `index.html`. The styling is in
`style.css`; it follows the system colour scheme, so it works in light and
dark without a toggle.
