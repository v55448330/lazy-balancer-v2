/**
 * 每个 IP 名单的条目上限（与后端 internal/handlers/securityiplists.go
 * `ipListMaxEntries = 2000` 同源）。SFC 内曾有 2000 双份硬编码（校验一处、
 * 文案一处），收敛于此；跨栈对表见 ipList.spec.ts。
 */
export const IP_LIST_MAX_ENTRIES = 2000

// IP 名单保存守卫：弹框以「空 entries 起步 → 详情
// GET 回填」加载。详情在途或失败时保存按钮若可点，会把空数组全量 PUT——直接
// 清空该名单（PUT 语义=全量替换）。守卫在此集中供模板/脚本同源消费。

/** 保存按钮可用性：详情在途或加载失败时禁止保存。 */
export function canSaveIpList(detailLoading: boolean, detailFailed: boolean): boolean {
  return !detailLoading && !detailFailed
}

/**
 * 「已有名单 + 提交条目为空」需要二次确认（文案必须明示清空）。
 * 新建空名单属于正常操作（后端 validateIPListShape 允许空），不弹确认。
 */
export function needsEmptyListConfirm(editingId: number | null, entries: number): boolean {
  return editingId !== null && entries === 0
}

/**
 * 全量 PUT 之前的新鲜度差集：服务端当前存在、但本次载荷已不含的条目值。
 *
 * 自动封禁名单由任务持续 merge 写入（攻击者达阈值即追加条目），而弹框详情只在
 * 打开时取一次、保存是整表替换——期间新增的封禁条目会被一并删掉（提前解封），
 * 界面无任何提示。按值（去空白、大小写不敏感）比对，重复值只报一次。
 */
function entriesMissingFromPayload(
  serverEntries: readonly string[],
  payloadValues: readonly string[],
): string[] {
  const keep = new Set(payloadValues.map((value) => value.trim().toLowerCase()))
  const reported = new Set<string>()
  const missing: string[] = []
  for (const raw of serverEntries) {
    const key = raw.trim().toLowerCase()
    if (!key || keep.has(key) || reported.has(key)) continue
    reported.add(key)
    missing.push(raw.trim())
  }
  return missing
}

/** 名单条目最小形状（value 为身份，其余字段随详情原样回写）。 */
interface IpListEntryLike {
  readonly value: string
  readonly remark?: string
  readonly created_at?: string
  readonly expires_at?: string
}

const entryKey = (value: string): string => value.trim().toLowerCase()

/**
 * 保存前的最终复核：把「打开弹框后由任务新增、本次载荷又没有」的封禁条目
 * 原样并入载荷，避免整表替换把它们删掉（提前解封）。
 *
 * 只看「打开快照里没有」的条目——打开时就存在、用户主动删掉的不算并发新增，
 * 否则手动解封会被静默回填，用户的删除动作失效。比对按值（去空白、大小写
 * 不敏感）去重，返回并入的条目与并入的值（供保存后显性提示）。
 */
export function mergeConcurrentBanEntries<T extends IpListEntryLike>(
  serverEntries: readonly T[],
  payloadEntries: readonly T[],
  openSnapshotValues: readonly string[],
): { entries: T[]; preserved: string[] } {
  const missing = new Set(entriesMissingFromPayload(serverEntries.map((entry) => entry.value), payloadEntries.map((entry) => entry.value)).map(entryKey))
  const knownAtOpen = new Set(openSnapshotValues.map(entryKey))
  const preserved: string[] = []
  const merged: T[] = [...payloadEntries]
  for (const entry of serverEntries) {
    const key = entryKey(entry.value)
    if (!missing.has(key) || knownAtOpen.has(key)) continue
    missing.delete(key)
    preserved.push(entry.value.trim())
    merged.push(entry)
  }
  return { entries: merged, preserved }
}
