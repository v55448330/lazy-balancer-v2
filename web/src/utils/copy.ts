const copyWithTextarea = (text: string): boolean => {
  const textarea = document.createElement('textarea')
  textarea.value = text
  textarea.setAttribute('readonly', '')
  textarea.style.position = 'fixed'
  textarea.style.opacity = '0'
  textarea.style.pointerEvents = 'none'
  document.body.appendChild(textarea)
  textarea.select()
  textarea.setSelectionRange(0, text.length)

  try {
    return document.execCommand('copy')
  } catch {
    // execCommand 仅抛 DOMException（Error 子类）；其余值同样按复制失败处理，不向外抛。
    return false
  } finally {
    textarea.remove()
  }
}

export const copyText = async (text: string): Promise<boolean> => {
  if (!navigator.clipboard) return copyWithTextarea(text)
  return navigator.clipboard.writeText(text).then(
    () => true,
    () => copyWithTextarea(text),
  )
}
