# AiFw Website

GitHub Pages site served from this directory. Published to:
**https://zerosandonesllc.github.io/AiFw/**

## Local development

```bash
cd docs
bundle install
bundle exec jekyll serve --livereload
# open http://localhost:4000/AiFw/
```

## Structure

```
docs/
├── _config.yml              # Jekyll config + SEO plugins
├── _layouts/default.html    # shared page layout
├── assets/
│   ├── style.css            # all CSS
│   └── *.png                # logos and icons
├── index.html               # landing page
├── features.md              # full feature list
├── compare.md               # AiFw vs OPNsense vs pfSense
├── install.md               # install guide
└── docs.md                  # docs index
```

Content is Markdown or HTML. Jekyll renders it through `_layouts/default.html`.

## Enabling GitHub Pages

One-time setup (GitHub web UI):

1. Go to **Settings → Pages**
2. Under "Build and deployment" → **Source: GitHub Actions**
3. The workflow in `.github/workflows/gh-pages.yml` deploys on every push to `main` that touches `docs/`

## Custom domain (later)

1. Add a `CNAME` file in `docs/` containing the domain (e.g. `aifw.io`)
2. In DNS: add `CNAME zerosandonesllc.github.io` or `A` records to GitHub's IPs
3. In Settings → Pages → enter the custom domain, enable HTTPS
4. Update `url` in `_config.yml` to match
