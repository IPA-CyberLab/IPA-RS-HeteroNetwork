# Mermaid browser bundle

`mermaid.min.js` is a self-contained browser bundle generated from the exact
versions in the repository `package-lock.json`.

Regenerate the bundle and its license notices with:

```sh
npm ci
npm run build:webui-vendor
```

The generated `mermaid.NOTICES.txt` contains package attribution and license
texts for dependencies that contributed code to the bundle. The generated
`mermaid.min.js.LEGAL.txt` contains legal comments retained by esbuild.
