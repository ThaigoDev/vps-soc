// Folds dist-presentation/presentation.html and its JS/CSS into one self-contained file:
//   ../docs/apresentacao/VPS-SOC-apresentacao.html
// The module script goes to the end of <body> so #root already exists when it runs.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const dist = join(root, 'dist-presentation')
const read = (rel) => readFileSync(join(dist, rel.replace(/^\.?\//, '')), 'utf8')

let html = read('presentation.html')
const scripts = []
html = html.replace(/<script type="module" crossorigin src="([^"]+)"><\/script>\s*/g, (_, src) => {
  scripts.push(read(src).replace(/<\/script/gi, '<\\/script'))
  return ''
})
html = html.replace(/<link rel="stylesheet" crossorigin href="([^"]+)">/g, (_, href) => `<style>${read(href)}</style>`)
// A function replacer: the bundle contains "$&"-like sequences a string replacement would expand.
html = html.replace('</body>', () => `${scripts.map((js) => `<script type="module">${js}</script>`).join('\n')}\n</body>`)

if (/(src|href)="\.?\/?assets\//.test(html)) throw new Error('an asset was left outside the file')
const out = join(root, '..', 'docs', 'apresentacao', 'VPS-SOC-apresentacao.html')
mkdirSync(dirname(out), { recursive: true })
writeFileSync(out, html)
console.log(`ok: ${out} (${(html.length / 1024 / 1024).toFixed(2)} MB)`)
