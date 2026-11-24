# restart-lsn-evidence — `$LogFile` 重启信息、LSN 定位链路与损坏页证据缺口

- 报告日期：2026-11-24
- 分析对象：仓库 `dfir_ntfs/LogFile.py`（提交 `ec3ae08`，`task/338` 分支）及其 `test_data/LogFile_*.bin`
- 分析方式：只读代码走查 + 用仓库自身解析器实测样本；所有"损坏/改字段"实验均在 `/tmp` 的**副本**上进行，未改动仓库与原始检材
- 仓库自测：`python3 -m pytest test_cases.py -k logfile -q` → `5 passed`

---

## 1. 结论摘要

1. **重启页与页面几何共同限定 LSN 起点和记录页范围。** 解析器固定从文件偏移 `0` 与 `4096` 读取两份 `RSTR` 重启页（`LogFile.py:658-659`），由重启区给出 `sequence_number_bits`、记录头长度、页数据偏移，由重启页头给出系统页/日志页大小；LSN 经 `lsn_to_offset()`（`LogFile.py:720-728`）换算成 `(日志记录页号, 页内偏移)`。**起点**必须区分三个层次：重启副本声明的客户端 `oldest LSN`（恢复地平线）、NTFS 检查点重启记录中的 `oldest/checkpoint LSN`、以及镜像中能逐字节验证的最早 LSN——三者不一定重合。
2. **两份重启副本在本仓库样本中确实存在"序列状态不一致"**（USA 写序号、current/client-restart LSN、oldest 地平线各不相同，且哪一份更新并不固定在第一页）；但**页面几何字段在随附样本中一致**（均为 4096 页、seqbits 43，`LogFile_7` 为 42）。对"几何/序列位也不一致"的题设情形，本报告用受控改字段实验确认了仓库代码的实际取舍（见第 4 节）。
3. **"某页可读"不等于"日志序列连续"。** 一页通过 USA 修复与签名检查，只能证明该页自身（的扇区保护）可解析；LSN 还必须精确落在几何偏移上且页头 `this LSN` 相等（`LogFile.py:830-831`），前后继链接还要逐跳验证。损坏页会使 `get_log_record_page_by_number()` 返回 `None`，对应 LSN 被剔除、链游走终止、跨页记录重组截断；缺口之后的页即使完全可读，也无法补回中间记录。实测仅弄坏 `LogFile_10.bin` 的第 46 页（一个 USA 字节），通过验证的 LSN 集合即从 **305 降到 254**，且损失沿链扩散到位于第 34、47 页的 LSN。
4. 样本中存在三类天然缺口/错位：`0xFF` 空页（如 `LogFile_10.bin` 第 4–12、16–17、32–33 页）、**可读但属于旧序列代际的页**（第 48–51 页承载 seq=2 记录，而最新重启 LSN 要求 seq=4 的同一几何位置）、以及 **LSN 指向文件尾之外的页**（`LogFile_7.bin` 的重启 LSN 指向第 42 页，而文件只有第 0–41 页）。尾部页/快速页修复机制可以在**内存副本**中补回其中一部分端点，但这属于"副本恢复"，不是原始连续序列的证明。

---

## 2. 仓库的日志定位链路（代码走查）

### 2.1 两层结构与固定几何入口

| 结构 | 位置/字段 | 代码 |
|---|---|---|
| 第一份重启页 | 文件偏移 `0`，读 `PAGE_SIZE=4096` | `LogFile.py:658` |
| 第二份重启页 | 文件偏移 `4096` | `LogFile.py:659` |
| 空日志判定 | 两份均为 `0xFF*4096` → `EmptyLogFileException` | `LogFile.py:664-665` |
| 重启页签名 | 接受 `RSTR`/`CHKD`/`BAAD` | `LogFile.py:240-242` |
| 强制页大小 | system/log page size 先做范围校验（非法抛 `RestartPageException`），再强制等于 `4096`（不符抛 `NotImplementedError`） | `LogFile.py:251-263` |
| 重启区偏移 | 重启页头 `+24` 的 `restart_offset`（样本均为 `0x30`=48） | `LogFile.py:265-267, 284-287` |
| 序列位 | 重启区 `+16 sequence_number_bits`（允许 3..63） | `LogFile.py:355-358, 713-715` |
| 记录头长度 | 重启区 `+36`（≥48） | `LogFile.py:380-383, 707-709` |
| 页数据偏移 | 重启区 `+38 log_page_data_offset`（样本均为 64） | `LogFile.py:385-388, 711` |
| 客户端地平线 | `ClientRecord.oldest_lsn`（+0）、`client_restart_lsn`（+8），记录长 160 | `LogFile.py:416, 426-434` |

注意：重启区 `+24` 还有一个声明的 `file_size`（`RestartArea.get_file_size()`，`LogFile.py:370-373`），但**定位链路从不使用它**；页范围边界只用文件对象的真实大小 `self.file_size`（`LogFile.py:654-655, 1269`）。对裁剪/雕刻样本，不能用重启区声明大小代替实际可读范围。

### 2.2 LSN → 物理位置的换算与回验

`lsn_to_offset()`（`LogFile.py:720-728`）：

```
absolute_offset = ((lsn << seqbits) & 0xFFFF…FFFF) >> (seqbits - 3)
page_number     = absolute_offset // log_page_size
offset_in_page  = absolute_offset %  log_page_size
seq_number      = lsn >> (64 - seqbits)          # lsn_to_seqnum, 730-733
```

逆运算 `offset_to_lsn()` 在候选后继处重建 LSN（`LogFile.py:735-740`）。这意味着 **LSN 本身编码了它应在的几何位置和序列代际**；定位不是"扫描到某个相似页"，而是"算术直达 + 头部 `this LSN` 严格相等"的双重验证：

- 目标页读取失败/截断/USA 或签名异常 → `None`（`LogFile.py:742-756`）；
- 映射到第 0 页的 LSN（含 LSN=0、`chkdsk_lsn`）直接剔除（`LogFile.py:815-817`）；
- 页为 `None`、偏移处头解析失败、或 `this_lsn != lsn` → 剔除（`LogFile.py:819-831`）。

### 2.3 记录页分区与"包装"几何

`get_wrapped_log_record_page_number()`（`LogFile.py:758-768`）与 `log_record_pages(mode)`（`LogFile.py:1254-1275`）给出固定分区：

| 版本 | 重启页 | 尾部/快速副本区 | 循环（"infinite"）记录区起点 |
|---|---|---|---|
| 1.1（`LogFile_7`、`..._downgraded`） | 0–1 | 尾部页 **2–3** | **第 4 页** |
| 2.0+（`LogFile_10`、`..._large`） | 0–1 | 32 个快速页 **2–33** | **第 34 页** |

全文件枚举 `mode=1` 从第 **2** 页开始，上界为 `file_size // log_page_size`（`LogFile.py:1265-1269`）。因此通用记录页范围公式为：

```
N = floor(实际文件字节数 / log_page_size)
可枚举记录页：2 .. N-1
v1.1：尾部 2–3；循环区 4 .. N-1
v2.x：快速页 2–33；循环区 34 .. N-1
```

但 LSN 算术可能指向第 `N` 页（裁剪样本中恰好在 EOF 之外）或更后的页；这些页**不在原始可读范围内**，只能由尾部/快速副本在内存中修复（见 3.3、5.2）。

### 2.4 连续性是"验证出来的图"，不是页号相邻

`collect_lsns()`（`LogFile.py:770-1147`）的种子来自：两份重启页的 chkdsk/current LSN、各客户端的 oldest/restart LSN（775-801），以及每个记录页头的 `last_lsn`/`last_end_lsn`（803-808）。随后：

- `find_next_lsn()`：按 `记录头长 + client_data_length` 算同页候选，失败再试下一页 `log_page_data_offset` 处；跨文件尾包装时页号回到 4/34 且 `seqnum_expected += 1`（`LogFile.py:886-920, 906-910`）；多页记录按页容量跳页计算（922-963）。候选必须 `this LSN == 推算 LSN` 才成立。
- `find_previous_lsn()` / `find_undo_next_lsn()`：沿记录头中的客户端前驱/undo-next 指针做同样的"指针换算 + this LSN 回验"（`LogFile.py:965-1027`）。
- 任一目标页为 `None` 或头不匹配，该方向游走立即终止（返回 `None`）。
- 跨页取客户端数据时，后续页为 `None` 就 `break`，得到截断的 `ClientData`（`LogFile.py:1297-1319`，关键断点 `1304-1306`）。

---

## 3. 可用重启信息支持的起点与页范围（实测锚点）

### 3.1 两份重启页的序列/几何核对

USA 序号是重启页写序的直接线索（位于 USA 偏移处，样本均为 `0x1E`）。**哪一份更新并不固定**，而仓库在两份都能构造时硬编码使用偏移 0 的第一份（`LogFile.py:693-705`），并不按 USA 序号或 LSN 新旧选择：

| 样本（大小/页数 N） | 页 0 USA 序号 / current LSN | 页 4096 USA 序号 / current LSN | seqbits / 页几何 | 仓库实际采用 |
|---|---|---|---|---|
| `LogFile_10.bin`（212,992 B / 52 页，0–51） | `0x0D`，**8,413,528 (`0x806158`)** | `0x0C`，8,413,349 (`0x8060A5`) | 43 / 4096，dataoff 64，hdr 48，v2.0 | 页 0（恰好较新） |
| `LogFile_10_downgraded.bin`（52 页） | `0x0011`，8,414,383 (`0x8064AF`) | **`0x0012`（较新）**，同值 8,414,383 | 43 / 4096，v1.1 | 页 0（较旧写序，但 LSN 已收敛） |
| `LogFile_10_large.bin`（225,280 B / 55 页，0–54） | `0x0007`（较旧），4,222,293 (`0x406D55`) | **`0x0008`（较新）**，4,222,581 (`0x406E75`) | 43 / 4096，v2.0 | **页 0（较旧的检查点）** |
| `LogFile_7.bin`（172,032 B / 42 页，0–41） | `0x0007`，8,410,141 (`0x80541D`) | `0x0007`，逐字节相同 | **42** / 4096，v1.1 | 两份等价 |

仓库只交叉校验两份的 `log_page_size` 与版本元组是否相等（`LogFile.py:697-702`），**不比较** `sequence_number_bits`、current/oldest LSN、USA 序号、`record_header_length`、`log_page_data_offset`。测试代码反而示范了鉴定时应做的新旧取舍：比较两份的 `client_restart_lsn` 取较大者（`test_cases.py:1218-1221`）。

### 3.2 `LogFile_10.bin`：起点的三个层次与第 48 页代际错位

用 seqbits=43 计算（LSN 低 21 位 ×8 为字节偏移）：

| 锚点（来源） | LSN | seq 代际 | 几何归宿 | 原始镜像回验 |
|---|---|---|---|---|
| 页 0 current = client restart | 8,413,528 `0x806158` | 4 | **第 48 页 +2752** | 页可读，但 `this LSN` **不匹配** |
| 页 0 client oldest（最新副本的恢复地平线） | 8,413,349 `0x8060A5` | 4 | 第 48 页 +1320 | 同上，不匹配 |
| 页 1 current / restart | 8,413,349 `0x8060A5` | 4 | 第 48 页 +1320 | 不匹配 |
| 页 1 client oldest（上一副本的更宽地平线） | 8,412,382 `0x805CDE` | 4 | **第 46 页 +1776** | **匹配，可直接验证** |
| 原始镜像 collect 到的最早 LSN | 4,219,328 `0x4061C0` | 2 | 第 34–51 页群 | 验证通过（305 个 LSN） |
| 原始镜像 collect 到的最高 LSN | 8,413,167 `0x805FEF` | 4 | 第 34–47 页群 | 验证通过 |

第 48 页本身是 USA 有效、签名 `RCRD` 的可读页，但其页头 `last LSN=4,219,386`（seq=2 代际），与重启信息要求的 seq=4 同位置记录不是同一代数据——**这正是"页可读但序列不连续/不是所指记录"的实证**。

NTFS 客户端重启记录（`LfsClientRestart`）进一步给出检查点链。恢复后在 LSN 8,413,528 处解出的最新 `NTFSRestartArea`：`start_of_checkpoint=8,413,349`、OAT=8,413,369、属性名=8,413,503、其内部 `oldest_lsn=8,413,349`、bytes/cluster=4096；而 8,413,349 处的前一份 NTFS 重启区又声明 `checkpoint=8,412,988`、`oldest=8,412,382`。这与第二份重启页的客户端地平线吻合，说明**可证据化的恢复起点应表述为 8,412,382（第 46 页可直接验证），最新副本声明的 8,413,349/8,413,528 端点在原始位置缺失、需快速页恢复支持**。

记录页范围（52 页总量）：

- 重启页 0–1；v2 快速页 2–33；循环区 **34–51**（LSN 算术归宿与实测有效 LSN 均落在此区间）。
- 可解析 `RCRD` 页共 37 个：2–3、13–15、18–31、34–51；`0xFF` 不可解析页 13 个：4–12、16–17、32–33。
- 第 2、18 页是指向第 48 页（`offset@60=196608=48×4096`）的快速副本，分别携带 8,413,349、8,413,528；第 3 页指向第 46 页并携带 8,412,350。

### 3.3 尾部/快速页能补回什么（以及不能证明什么）

- **v2 快速页**（`apply_fast_pages`，`LogFile.py:1223-1252`）：先在循环区 34–51 找最高 `last_lsn`，再从 2–33 中挑 `last_lsn` 更高的快速页，按 LSN 升序写到其页头 `offset@60` 指向的几何位置（1238-1252）。对 `LogFile_10.bin`，第 2、18 页都写第 48 页，升序保证较新的第 18 页最后写入；随后 8,413,528 在内存副本中通过 `this LSN` 验证，测试中的 `found_client_restart_lsn` 由 False 变 True（`test_cases.py:1228-1294`）。
- **v1.1 尾部页**（`apply_tail_page`，`LogFile.py:1193-1221`）：比较第 2、3 页的 `last_end_lsn` 选新者，把其**受 USA 保护的原始字节**写到页头 `offset@8`（与 `last_lsn` 同字段，v1.1 复用为文件偏移，见 `LogFile.py:503-506`）。

`LogFile_7.bin` 是"起点/端点在 EOF 之外、仅尾部副本幸存"的清晰案例：

- current/restart LSN 8,410,141（seqbits=42，seq=2）→ 字节偏移 172,264 = **第 42 页 +232**；oldest 8,410,130 → 第 42 页 +144。文件实际只有 42 页（0–41，172,032 B），故原始状态 `get_log_record_page_by_number(42)` 短读返回 `None`，三个重启锚点全部验证失败。
- 原始 collect：776 个 LSN，最早 8,390,684 (`0x80081C`)，最高 8,410,095，归宿页恰为 **4–41**（与 v1.1 循环区公式一致）。
- 第 2 页 `last_end_lsn=8,410,141` 新于第 3 页的 8,410,130，两者 `offset@8=172032=42×4096`（即 EOF/第 42 页起点）。应用尾部页等于在内存 `BytesIO` 末尾**扩展出第 42 页**；恢复后得到 778 个 LSN，最高为 8,410,141，最新 NTFS 重启区（LSN 8,410,141，v0.0）声明 checkpoint=oldest=8,410,130。

`LogFile_10_large.bin` 则提示"盲信第一份重启页"的边界：较新的第二份（USA `0x08`）current LSN 4,222,581 指向第 **55** 页 +936，而文件只有 0–54 页；仓库采用的第一份（USA `0x07`）current 4,222,293 与 oldest 4,222,111 均在第 54 页直接验证。鉴定结论应说明：**仓库当前采用的是一个可自洽验证但较旧的检查点，最新重启副本的端点在本裁剪样本中不在原始页内。**

### 3.4 重启区声明文件大小与实际样本不符（几何注意事项）

`LogFile_10*` 重启区声明 `file_size=9,043,968`（2208 个 4096 页），`LogFile_7` 声明 23,560,192（5752 页），均远大于随附样本的实际字节（52/55/42 页）。如 2.1 所述，该字段不参与定位；这与测试依赖尾部/快速页恢复缺失端点的现象一致。制作鉴定笔录时，页范围必须以**实际取到的镜像字节 + LSN 算术回验**为准，不能照抄重启区 FileSize。

---

## 4. "两份重启信息在序列与几何上不一致"时的代码实际行为（受控副本实验）

以下均在 `/tmp` 临时副本上改动少量字段字节后用仓库代码实测：

| 实验（针对 `LogFile_10.bin`，除非另注） | 仓库行为 | 对鉴定的含义 |
|---|---|---|
| 仅把第二份页头 `log_page_size` 改成 8192 | `RestartPage` 抛 `NotImplementedError: ... log page size ... not supported: 8192`，且该异常**不被** `LogFileParser.__init__` 的 `except LogFileException` 捕获，构造直接失败 | 出现仓库不支持的几何时，整条解析链不可用，需独立解析；`LogFile.py:697-698` 的"两份 log page size 不一致"守卫在本版本下实际是防御性死分支——能构造成功的页都已被强制为 4096 |
| 第二份 `restart_offset` 置 0（软几何损坏） | `RestartAreaException` 被捕获 → `restart_page_2=None`，**静默回退页 0** | 一份损坏时另一份被全盘采用，不再有交叉核对；需在报告中注明唯一来源 |
| 第二份 USA 尾标记翻转 | 同上：USA 校验失败 → `restart_page_2=None`，采用页 0 | USA 失败即视为该副本不可用（`UnprotectSectors`，`LogFile.py:166-177`） |
| 两份 USA 都弄坏 | `LogFileException: No valid restart pages found` | 没有可用重启信息时，seqbits/几何/起点均无权威来源，不能由工具自行推定 |
| 第二份 seqbits 43→44（结构仍合法） | 无任何跨副本比较；解析器静默使用页 0 的 **43** | "序列位数分歧"不会被报警；若页 0 恰好损坏而回退到被改的一份，所有 LSN 都会被错误平移，可能表现为大量"页可读但 this LSN 不匹配" |
| 第一份（页 0）USA 弄坏 | `restart_page_1=None`，改用页 4096 的几何/重启区（`LogFile.py:683-686`） | 回退分支可用，但选取规则是"哪份没坏"，不是"哪份更新" |

---

## 5. 损坏页留下的证据缺口，以及为什么可读页不能证明连续

### 5.1 一页"可读"实际验证了什么

`LogRecordPage` 构造只做：USA 扇区修复/校验（`LogFile.py:483-489`）、签名属于 `RCRD/CHKD/BAAD`、以及 data_offset 基本约束（487-496）。因此"页可读"最多说明：

1. 各 512 字节扇区尾的 USA 标记与 USA 数组序号一致、fixup 已应用——页在写入时受保护且未发现典型撕裂/位损坏；
2. 签名合法（注意 `BAAD` 也在白名单内；把 `RCRD` 签名改成 `BAAD` 而不动 USA，仓库仍会返回该页对象且 305 个 LSN 全部保留——`BAAD` 在本实现中不触发额外隔离）；
3. 页头字段可解码。

它**不**保证：该页在 LSN 序列中的前驱/后继页存在、页内记录未被新版本覆盖、LSN 代际正确、或多页记录的其余页完好。这些必须通过 2.2/2.4 的几何回验与链接游走逐跳建立。

### 5.2 缺口的三种实测形态

**(a) 物理损坏/空白页 → 定位返回 `None`，锚点被剔除、游走终止。**
`LogFile_10.bin` 第 4–12、16–17、32–33 页为 `FF FF FF FF …`：其伪造的 `usa_offset=0xFFFF` 立即越界，`UnprotectSectors` 抛异常，`get_log_record_page_by_number()` 吞掉 `LogFileException/NotImplementedError` 返回 `None`（`LogFile.py:751-754`）。这些区间没有任何可引用的记录。

受控因果实验（副本）：

- 翻转第 **46** 页第一个扇区尾（页内偏移 510）的 USA 标记字节：该页变为 `None`；`collect_lsns()` 验证集合 **305 → 254**。消失的 51 个 LSN 中，25 个归宿于第 46 页本身，另有 23 个归宿第 34 页、3 个归宿第 47 页——非局部损失来自链接游走在断点处终止、且这些 LSN 没有独立页头种子。重启锚点 **8,412,382 同时失去验证**。（改为翻转末扇区偏移 4094 处的标记，计数同样为 305→254。）
- 把第 **40** 页签名改成非法 `ZZZZ`：**305 → 268**。
- 弄坏本来就是 `0xFF` 的第 8 页：数量不变（305）。**损害后果取决于该页实际承载的链接价值，不能按"坏了几页"估算丢失记录数。**

**(b) 可读但代际错误的页 → 几何位置存在，LSN 身份不成立。**
`LogFile_10.bin` 第 48–51 页全部是 USA 有效的 `RCRD`，但承载 seq=2 的旧循环代际；最新重启信息（seq=4）算术直达第 48 页后 `this LSN` 校验失败，两个重启 LSN 在原始 collect 中均不成立。第 13–15、23–31 页则是更旧的快速/副本岛。**不能因为第 48 页可读就宣称从 8,412,382 到 8,413,528 的序列在原始镜像中连续**；中间的当前代内容已被循环覆盖，只有快速页 2/18 保留了端点副本。

**(c) LSN 指向实际字节范围之外的页 → 原始证据只存在于尾部副本。**
`LogFile_7.bin` 第 42 页、`LogFile_10_large.bin` 第 55 页都是 LSN 算术合法但文件短读的页。原始状态下这些重启端点不可验证；v1.1 尾部页/ v2 快速页可在**内存可写副本**中把它们重建出来（`prepare_for_writes` → BytesIO，`LogFile.py:1168-1181`；解析结束 `discard_changes`，1396-1397）。鉴定时必须区分"原始偏移上的证据"与"用副本在内存恢复出的证据"，并在笔录中记录恢复来源页。

### 5.3 多页记录在缺口处被截断

页头的 `page_count/page_position`（`LogFile.py:519-527`）表明一条记录可跨多页（如 `LogFile_10.bin` 第 19–22 页头部标注 `page count=5, position=2..5`）。`get_client_data()` 按 `log_page_data_offset` 逐页拼接，遇到 `None` 页直接 `break`（`LogFile.py:1297-1316`），随后 `ClientData.data_decoded()` 可能因长度不足抛 `ClientException`，或交出语义不完整的缓冲区。因此即使记录头所在页完好，只要跨页链上有一页损坏，该记录的 redo/undo 数据就不能作为完整证据引用。

### 5.4 可主张与不可主张的边界

在题设"两份重启信息序列与几何不一致 + 存在损坏页"的情形下，严谨的鉴定表述应是：

- **可以主张**：每份结构合法的重启副本各自声明的几何与 LSN 锚点；其中通过"LSN→几何偏移 + `this LSN` 相等"回验的锚点/记录；由验证过的前驱/后继指针逐跳连通的 LSN 子链；尾部/快速副本在注明来源后支持的恢复端点。
- **不能主张**：跨越 `None` 页、签名/USA 失败页、`this LSN` 不匹配页的连续性；仅凭相邻页号或某页 `RCRD` 可读就推断中间记录存在且完整；把旧序列代际页当作最新重启 LSN 所指记录；把内存修复结果表述为原始偏移上仍存在该页；在两份重启页几何/序列位冲突且无外部依据时，断言唯一的"日志起点"。
- **缺口的证据含义**：缺口区间内的事务可能存在但当前检材不可证；序列不连续是**可见的证据缺口**，而不是"日志没有相关操作"的肯定结论。

---

## 6. 给本仓库解析链的操作化判定顺序

1. 读偏移 0/4096 两份重启页；分别记录：签名、USA 序号、版本、system/log page size、restart_offset、seqbits、hdr/data offset、current/oldest/restart LSN。
2. 按"一份损坏用另一份、两份皆坏终止、两份皆好用页 0 且强制几何/版本相等"的真实规则确定解析参数；**鉴定报告另行按 USA 序号与 LSN 大小判断哪份更新**，不把工具的页 0 选择等同于最新检查点。
3. 用实际文件大小计算 `N=floor(size/page_size)`，给出记录页总范围与 4/34 包装起点；不要使用重启区声明的 FileSize 划界。
4. 对每个起点候选（client oldest、NTFS checkpoint/oldest、current/restart）执行 LSN→页/偏移换算与 `this LSN` 回验；标注其状态：`原始位置已验证 / 代际不符 / EOF 之外 / 损坏缺失 / 仅尾部或快速副本可恢复`。
5. 枚举第 2..N-1 页，列出有效 `RCRD` 页与 `None` 页；以验证过的 LSN 集合及其归宿页描述实际覆盖，而不是假设页号连续。
6. 需要最新端点时，在副本上启用 tail/fast 恢复，并单独记录被覆盖/扩展的目标页与来源副本页。
7. 任何跨损坏页的序列结论一律降级为"不可证"。

---

## 附录 A：关键实测数值索引

- 样本哈希（SHA-256）：
  - `LogFile_10.bin` `a3e908923404ae806f755fb223a62b2838ca59a38eca49a32c1cb17ada6220c5`
  - `LogFile_10_downgraded.bin` `162fb28e4956ff6359e76325f8f0e61af1c720dabac9770992bc507abe2c7e41`
  - `LogFile_10_large.bin` `f7921e4f872f02a6d9d2e81e72d45251bf2045d03dd3586d3804d1570ea447aa`
  - `LogFile_7.bin` `9b8948dc5b8b66e93f480a79eacb4440e8c6e939511ec35957222962379390d7`
- 重启页布局实测：签名 `RSTR`；USA offset=30、count=9；restart area offset=48；seqbits 43（`LogFile_7`=42）；record header length=48；log page data offset=64；NTFS 单客户端，ClientRecord 长 160。
- 典型换算复核：
  - `0x806158` @ seqbits43 → seq 4，页 48 +2752；
  - `0x805CDE` @43 → 页 46 +1776（`this LSN` 匹配）；
  - `0x80541D` @ seqbits42 → seq 2，页 42 +232（EOF 外）；
  - `0x406D55` @43 → seq 2，页 54 +2728（匹配）；`0x406E75` → 页 55 +936（EOF 外）。

## 附录 B：只读复核命令示例

```bash
# 仓库自测
python3 -m pytest test_cases.py -k logfile -q

# 用隔离模式运行只读探针（脚本自行 sys.path.insert 仓库路径，检材路径以参数传入）
python3 -I /tmp/lfn-analysis/probe_restart.py \
  /srv/fb2/mei8085/0338-dfir-ntfs-6-926d339a/test_data/LogFile_10.bin
```

最小化的字段/LSN 复核可直接用仓库模块：

```python
import sys; sys.path.insert(0, "/srv/fb2/mei8085/0338-dfir-ntfs-6-926d339a")
from dfir_ntfs.LogFile import LogFileParser
p = LogFileParser(open("test_data/LogFile_10.bin", "rb"))
print(p.log_version, p.sequence_number_bits, p.log_page_size,
      p.record_header_length, p.log_page_data_offset)
print(p.get_wrapped_log_record_page_number(), p.file_size // p.log_page_size)
print(p.lsn_to_offset(8413528), p.lsn_to_seqnum(8413528))   # (48, 2752), 4
```

> 注：附录中的 `/tmp/lfn-analysis/` 探针是本次分析使用的临时脚本；报告内所有结论与数值均可由上述代码位置和命令独立复核。
