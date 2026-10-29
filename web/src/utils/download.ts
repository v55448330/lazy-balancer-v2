/**
 * 浏览器下载单源：配置备份、自动备份、IP 名单 CSV、MCP 手册四路导出共用。
 *
 * Safari 下立即回收 objectURL 会截断下载文件，故延迟 1s 再释放——这条时序
 * 知识只允许存在于此处（此前四个视图各自拷了一份，任一处改进都不会传播）。
 */
export const saveBlob = (blob: Blob, filename: string): void => {
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
