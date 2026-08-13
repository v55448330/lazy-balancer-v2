import Prism from 'prismjs'
import 'prismjs/themes/prism-okaidia.css'
import 'prismjs/components/prism-markup'
import 'prismjs/components/prism-css'
import 'prismjs/components/prism-clike'
import 'prismjs/components/prism-apacheconf'
import 'prismjs/components/prism-nginx'
import 'prismjs/components/prism-http'
import 'prismjs/components/prism-ini'
import 'prismjs/components/prism-json'

export const highlightCode = (content: string, language: string): string => {
  if (!content) return ''
  const lang = language || 'markup'
  const grammar = Prism.languages[lang] || Prism.languages.markup
  try {
    return Prism.highlight(content, grammar, lang)
  } catch {
    return content.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  }
}
