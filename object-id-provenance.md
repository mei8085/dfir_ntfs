# NTFS 对象标识的证据 provenance：身份、时间与卷归属

本报告基于 dfir_ntfs 1.1.20（`dfir_ntfs/__init__.py`）的源码与 `test_data/` 中的样本，说明三件事
在取证上必须分开陈述：

1. **对象身份**（这个对象是"谁"）——由 `$OBJECT_ID` 的 GUID、MoveTable 中的 object ID/DROID、
   `$MFT` 文件引用号（记录号 + 序列号）等给出；
2. **时间来源**（"什么时候"）——由 `$STANDARD_INFORMATION`/`$FILE_NAME` 的 FILETIME、
   GUID 版本 1 时间戳、MoveTable 日志项的时间带、USN 记录时间等给出；
3. **卷归属**（"在哪块卷上 / 出生于哪块卷"）——由引导扇区序列号、`$VOLUME_NAME`、
   `$VOLUME_INFORMATION`、GPT/MBR、卷影副本 GUID、MoveTable 头部卷 GUID、日志项的
   DROID 卷字段 / birth DROID 卷字段给出。

这三类字段虽然常在同一个属性或同一条日志项里相邻出现，但**代码没有任何一处把它们连成一条
可验证的链**。下面先逐类列出可用证据及其解析位置，再集中列出无法确定的环节，最后用仓库
自带样本证明"对象生成时刻不能替代文件创建时刻"。

---

## 0. 结论摘要

| 命题 | 能否由本代码直接支持 | 依据 |
|---|---|---|
| `$OBJECT_ID` 前 16 字节是一个 GUID，版本 1 时含生成时间戳 | 能 | `Attributes.py:494-511` |
| 该 GUID 是该文件的唯一身份 | 只能算**候选身份**，无唯一性校验、无 `$ObjId` 索引比对 | 无 `$Extend\$ObjId` 解析（全仓库无 `$ObjId` 代码），见 §1.6 |
| 该 GUID 的生成时间 = 该文件的创建时间 | **不能** | §5 实测：51 个版本 1 GUID 只落在 7 个时间带上，最大 18 个文件共享同一时间戳 |
| GUID 内嵌卷 / 出生卷信息 | 磁盘上有扩展形式，但本代码只把第 16 字节之后当不透明字节 | `Attributes.py:513-516` `get_extra_data()` |
| MoveTable 能把对象 ID 关联到 `$MFT` 记录号 | **不能** | 日志项结构无 MFT 引用字段，`MoveTable.py:195-241` |
| MoveTable 的 birth DROID 卷 = 当前卷 | 不能由代码判定；样本中 birth DROID 卷等于日志头部卷，但与 DROID 卷不同 | `MoveTable.py:201-241`；§4.2 |
| 卷 GUID、引导扇区序列号、GPT 分区 GUID 是同一个卷标识 | **不能** | 代码从不做此映射，见 §3 |
| 日志项时间带给出事件时刻 | 只能给出约 429.5 秒宽的区间 | `MoveTable.py:243-255` |

---

## 1. 证据一：对象身份

### 1.1 `$OBJECT_ID` 属性（记录级）

- 类型码 `0x40`：`Attributes.py:15`；在支持列表与解码表中注册：`Attributes.py:35`、
  `Attributes.py:1093`。
- 取值解析：`ObjectID.get_object_id()` 取 `self.value[0:16]`，按 **小端字节序**
  (`uuid.UUID(bytes_le = ...)`) 构造 UUID；不足 16 字节时返回 `None`
  （`Attributes.py:497-504`）。字节序若按大端读会得到完全不同的 GUID，这是一个常见的
  转写错误来源。
- 第 16 字节之后的内容：`get_extra_data()` 原样返回（`Attributes.py:513-516`），
  打印时只说 "Extra data is set"（`Attributes.py:518-525`）。公开格式里扩展形式
  （含 BirthVolumeId / BirthObjectId / DomainId 等）就位于这些字节中，但本代码**不做结构化解码**，
  因此"出生卷"信息即使写在属性里，也无法通过本解析器还原。
- 长度校验：`ObjectID` 继承 `GenericAttribute`（`Attributes.py:220-227`），构造时**不校验**
  公开格式中的 16/32/48/64 字节这几种长度；只在实际取值时兜底返回 `None`（`Attributes.py:500-504`）。
  仓库样本中所有 `$OBJECT_ID` 都是 16 字节（对 `test_data/*.mft` 全量扫描得到），
  但这只是样本特性，不能当作格式保证。

### 1.2 GUID 内部字段的可读性

`get_object_id()` 返回的是 `uuid.UUID` 对象，因此调用方可以访问 `version`、`time`、
`node`、`clock_seq`。代码只主动使用了 `version` 与 `time`（`Attributes.py:506-511`），
`node` 仅在测试里被断言过（`test_cases.py:3441`、`3444`、`3528-3529`），CLI 输出中从不出现。

按版本 1 语义，`node` 通常是生成端网卡 MAC。样本中可直接观察到这一点：

| 样本 | GUID 前缀示例 | `node` | 含义 |
|---|---|---|---|
| `nist-hacking-case.mft`（51 个版本 1） | `53d29f0e-f2ba-11d8-b0f9-...` | `00:10:a4:93:3e:09` | 全局管理单播 MAC（可作设备线索） |
| `unicode.mft`、`slack.mft`、`deleted.mft` | `...-525400123456` | `52:54:00:12:34:56` | 本地管理地址，QEMU/KVM 默认 MAC |
| 同一 MFT 的 `$Volume`（FRS 3） | `764dbc66-cebf-40e1-...` | 随机（版本 4） | 卷级对象 ID，无时间、无 MAC |

这说明 GUID 的 `node` 字段可以支撑"这批对象由同一台/同一类生成端产生"的判断，
但它**不**说明卷归属，也**不**说明当前所在卷。

### 1.3 `$Volume` 记录上的 `$OBJECT_ID`

`$MFT` 的第 3 号记录（`FILE_NUMBER_VOLUME`，`MFT.py:32`）同样带 `$OBJECT_ID`，
样本里它是版本 4（随机）GUID，例如 `nist-hacking-case.mft` 的
`764dbc66-cebf-40e1-a089-668bf908bd89`、`deleted.mft` 的
`328aa258-da3f-4bcb-ab6d-39683990d99d`。这是"卷级对象 ID"，与引导扇区序列号
（`BootSector.py:121-124`）、GPT 分区 GUID（`PartitionTable.py:35`）是**三个互不相同的量**，
代码中没有任何一处把它们相等化或互相映射。

### 1.4 MoveTable（`tracking.log`）中的标识

`MoveTable` 于 1.0.7 加入（`ChangeLog:164-167`），日志项为 124 字节定长结构，
解析位置 `MoveTable.py:195-241`：

| 字段 | 偏移 | 方法 | 说明 |
|---|---|---|---|
| Object ID | 20..36 | `get_object_id()` | 移动对象的 GUID |
| DROID 卷字段 | 36..52 | `get_droid()[0]` | 域相对对象 ID 的卷部分 |
| DROID 对象字段 | 52..68 | `get_droid()[1]` | 域相对对象 ID 的对象部分 |
| Machine ID | 68..84 | `get_machine_id()` | 生成端主机名（`DecodeString`，`MoveTable.py:30-50`） |
| Birth DROID 卷字段 | 84..100 | `get_birth_droid()[0]` | 出生域的卷部分 |
| Birth DROID 对象字段 | 100..116 | `get_birth_droid()[1]` | 出生域的对象部分 |

样本中的实测关系（`tracking_4kn.bin` 9 条、`tracking_512_large.log` 30 条）：

- 每条日志项的 DROID 对象字段与 Object ID **逐字节相同**（9/9、30/30）；
- Birth DROID 对象字段同样相同（9/9、30/30）；
- Birth DROID 卷字段 = 头部 `volume_object_id`（9/9、30/30）；
- DROID 卷字段是另一台卷的 GUID（`891b42ce-...`、`a969eb5a-...`），与头部卷 GUID 不同。

即：样本恰好呈现"从卷 A 迁移到卷 B（当前卷）"的形态，但**这些字段的语义没有被代码或测试
断言过**，`get_droid()` / `get_birth_droid()` 只做字节切分与 UUID 解码。报告里可以说
"字段值不同"，不能说"代码已验证这是一次跨卷移动"。

### 1.5 `$MFT` 文件引用号（记录号 + 序列号）

- 编码/解码：`MFT.DecodeFileRecordSegmentReference` / `EncodeFileRecordSegmentReference`
  （`MFT.py:77-88`），高 16 位序列号，低 48 位记录号。
- 记录头字段：`get_sequence_number()`（`MFT.py:301-304`）、
  `get_master_file_table_number()`（`MFT.py:351-361`）。
- 注意两个削弱点：
  1. 短记录头（Linux ntfs3 驱动写出，`usa_offset < 48`）时，记录号直接采用调用方传入的
     `suggested_mft_number`，并非从盘上读出（`MFT.py:355-356`）；
  2. 对**未分配**记录，代码按"释放时序列号 +1"的假设计算参考号
     （`MFT.py:1025-1031`、`1050-1056`、`1346-1352`），并在注释中明确写道
     "Some sources state something different from that"——这本身就是一处**未定论的语义**。
     因此用 USN 记录去匹配已删除文件时，序列号对不上属于预期行为，不能直接判定为"不同文件"。
- 路径重建：`build_full_paths()`（`MFT.py:1165-1279`）用 `$FILE_NAME` 的 parent reference
  逐级上溯，遇到序列号不符或父项不是目录则填入 `<Orphan>`（`MFT.py:16`、`1233-1272`）。
  这条链只说明"当前记录树里的位置"，不说明历史位置。

### 1.6 缺失的身份证据源

- **`$Extend\$ObjId` 索引未实现**。`FILE_NUMBER_EXTEND = 11` 只作为常量存在
  （`MFT.py:40`），全仓库没有任何解析 `$ObjId`（GUID → 文件引用号）的代码，
  也没有 `$Quota`/`$Reparse` 的处理。这意味着：手里只有对象 GUID 时，
  本工具**无法**在自己的实现里把它解析回某个 `$MFT` 记录，反之亦然。
- **`$OBJECT_ID` 的 birth volume / domain ID 未解码**（见 §1.1），所以"这个对象出生在哪个
  域/卷"在属性层面拿不到结构化字段。
- **USN 记录不含对象 ID**。`USN.py` 只解析引用号、父引用号、USN、时间、原因、源、属性、
  文件名（`USN.py:179-210`、`293-336`）。虽然定义了
  `USN_REASON_OBJECT_ID_CHANGE = 0x00080000`（`USN.py:26`、`51`），
  但 CLI 的 `--usn` 输出不打印对象 ID，也没有"对象 ID 变更"的专门关联逻辑。
- 因此对象身份的可达证据是：**GUID（含 node） / 文件引用号 / 路径** 三套彼此独立的键，
  代码没有提供它们之间的连接件。

---

## 2. 证据二：时间来源

### 2.1 文件时间（FILETIME，1601 纪元）

- 解码：`DecodeFiletime()`（`Attributes.py:153-162`，异常时返回 `None` 而不是抛错）。
- `$STANDARD_INFORMATION` 的 M/A/C/E：`Attributes.py:243-265`。
- `$FILE_NAME` 的 M/A/C/E：通过 `DuplicatedInformation`（`Attributes.py:392-420`），
  `FileName` 以 8 字节为偏移继承之（`Attributes.py:449-453`）。
- 这两个属性的 C 时间**都可由用户态 API 改写**（`$SI` 直接可写；`$FN` 有隧道/时间戳保留的影响），
  本代码不做任何一致性校验，也不告警两者不一致。

### 2.2 GUID 时间戳（1582 纪元，100 ns）

- 解码：`DecodeGUIDTime()`，`datetime(1582, 10, 15) + timedelta(microseconds = Timestamp/10)`
  （`Attributes.py:164-173`）。
- 取用：`ObjectID.get_timestamp()` **仅当 `guid.version == 1`** 时返回时间，
  版本 4 返回 `None`（`Attributes.py:506-511`）。
- 关键性质：
  - 纪元与 FILETIME 相差 6653 天（约 18.2 年），把它当 FILETIME 解读会整体偏移 18 年；
  - 版本 4 没有时间字段，"无时间"与"时间不可解析"在输出里都表现为 `N/A`
    （`ntfs_parser:10-15`），二者不可区分；
  - 时间戳只是 GUID 的生成时刻（见 §5 的实测反例）。

### 2.3 MoveTable 日志项的时间带

`LogEntry.get_timestamp()`（`MoveTable.py:243-255`）读取偏移 116..120 的 32 位值，然后：

```
lowest  = value << 32
highest = lowest | 0xFFFFFFFF
```

即只保留"秒"精度，得到的区间宽度恒为 `0xFFFFFFFF` × 100 ns = **429.4967295 秒
（约 7 分 9.5 秒）**。方法文档明确写 "The real event took place not before 'timestamp_lowest'
and not after 'timestamp_highest'"。实测两条含日志项的样本（`tracking_4kn.bin`、`tracking_512_large.log`）中每条区间的宽度都恰好等于该值。

`LogEntry.get_guid_timestamps()`（`MoveTable.py:257-277`）另外返回 Object ID / DROID 对象 /
birth DROID 对象三者的版本 1 时间戳（非版本 1 时为 `None`）。

### 2.4 USN 与 `$LogFile`

- USN v2/v3 记录时间：`USN.py:206-210`（FILETIME 解码）。
- USN v4（范围跟踪记录）**没有时间戳方法**（`USN.py:257-362` 只有引用号、USN、原因、源、
  extent）；CLI 对 v4 直接输出空时间（`ntfs_parser:309-314`）。因此"v4 记录没有时间"是
  格式限制，不是数据缺失。
- `$STANDARD_INFORMATION` 里还有 USN 值（`Attributes.py:333-339`），
  `$MFT` 记录头有 LSN（`MFT.py:296-299`、`887-890`）。这两个都是**逻辑序号**，
  本代码没有把它们换算成时间的实现；`$LogFile` 解析器整体也**没有任何时间字段**
  （`LogFile.py` 中无时间戳方法，只有 LSN；journal 引用与基址在 `LogFile.py:1530-1542`）。

### 2.5 卷影副本时间

`ControlBlockItem2.get_timestamp()` 解析 shadow copy 的提交时间（FILETIME，
`ShadowCopy.py:368-372`），经 `shadows()` 暴露（`ShadowCopy.py:718-728`）。
这是"快照时刻"，不是文件时间，也不是卷创建时间。

### 2.6 没有任何"卷/文件系统建立时间"

引导扇区解析器只提供几何结构、`$MFT` 位置、序列号（`BootSector.py:37-129`），
没有卷创建时间；MoveTable 头部只有若干 `unknown_timestamp_int_40/48` 字段，
名字就标着 unknown（`MoveTable.py:103-121`）。所以"卷何时被格式化/何时挂载"
这类时间在本工具里没有证据来源。

---

## 3. 证据三：卷归属

| 证据 | 解析位置 | 能说明什么 | 局限 |
|---|---|---|---|
| 引导扇区卷序列号（偏移 72..80） | `BootSector.py:121-124` | 卷的 NTFS 序列号 | CLI 不输出（`ntfs_parser` 中没有对 `get_serial_number()` 的调用），不与其他标识做映射 |
| `$VOLUME_NAME` | `Attributes.py:620-631` | 卷标 | 可改、可空、非唯一 |
| `$VOLUME_INFORMATION` 版本/标志 | `Attributes.py:634-658` | NTFS 版本、脏标志等 | 标志里 `0x8`（对象 ID/配额/USN 元数据可能损坏）与 `0x20`（需要修复对象 ID）直接提示 `$OBJECT_ID` 可能不可靠（`Attributes.py:45`、`47`） |
| GPT 分区唯一 GUID | `PartitionTable.py:35`、`197-214` | 分区级标识 | 与 NTFS 卷序列号/卷对象 ID 无映射 |
| MBR 磁盘签名（偏移 440..444） | `PartitionTable.py:37`、`261` | 磁盘级标识 | 同上 |
| 卷影副本卷 GUID / store GUID | `ShadowCopy.py:199-208`、`353-372`、`410-418` | VSS 存储/卷标识、快照时间 | 与 NTFS 卷对象 ID 无映射 |
| MoveTable 头部 `volume_object_id` | `MoveTable.py:103-121` | 记录该日志所属卷的 GUID | 文档注明"expected to be random (not based on a MAC address and time)"，即与卷序列号无关 |
| MoveTable 项 DROID 卷 / birth DROID 卷 | `MoveTable.py:201-241` | 当前域卷 / 出生域卷 | 语义未被代码或测试断言；不与任何分区/序列号比对 |
| `$Volume` 记录的 `$OBJECT_ID` | `Attributes.py:494-511` + `MFT.py:32` | 卷级对象 ID | 样本中为版本 4（无时间）；与 MoveTable 头部卷 GUID 未建立关系 |

结论式表述应当写成：
"该卷的引导扇区序列号为 X、GPT 分区 GUID 为 Y、卷对象 ID 为 Z"——
**而不是**"该卷的唯一标识是 X"。三者是不同层面的标签，本工具不提供等价性证明。

另外，`--all-mft` 模式会把主卷和每个卷影副本分别遍历，并用 `source` 列区分
（`ntfs_parser:195-197`、`863-881`、`format_source` `ntfs_parser:67-75`）。
这意味着同一路径/同一 GUID 可以出现在多行中，`source` 列才是"这是哪份视图"的字段，
不能把不同 source 的行合并计数。

---

## 4. 无法确定的环节（必须显式标注为不确定）

### 4.1 对象 GUID ↔ 卷

- `$OBJECT_ID` 的扩展字节没有解码（`Attributes.py:513-516`），所以属性里若含 BirthVolumeId，
  本工具读不出来。
- 没有 `$ObjId` 索引解析，也没有 DomainId 处理。
- 因此：**"这个对象出生于哪块卷"在本工具的输出里没有落脚点**。只能在 MoveTable 中看到
  birth DROID 卷字段，而该字段无法回连到任何卷的序列号/分区 GUID/卷对象 ID。

### 4.2 出生卷 ↔ 当前卷 ↔ 当前盘上的物理卷

- MoveTable 提供了三组卷字段（头部卷 GUID、DROID 卷、birth DROID 卷），样本中
  DROID 卷 ≠ 头部卷 = birth DROID 卷；但代码没有任何比较、判定或告警
  （`MoveTable.py:195-241` 只是取值）。
- MoveTable 日志项里**没有 MFT 引用号**，也没有卷序列号，无法把它与 `$MFT` 的某条记录或
  某个分区对齐。
- 结论：可以报告"日志显示该对象在卷 A 与卷 B 的 ID 空间之间出现过"，但**不能**据此断言
  磁盘镜像中的哪一块卷对应 A 或 B，除非另有独立证据（如 `$Volume` 记录、卷标、序列号）
  手工比对。

### 4.3 对象 ID 的历史（变更、复制、复用）

- 对象 ID 可通过 `NtSetInformationFile` 改写；USN 侧只有
  `USN_REASON_OBJECT_ID_CHANGE`（`USN.py:26`、`51`），CLI 不输出对象 ID，故无法从
  `--usn` 结果里看出"何时改成了什么"。
- 记录槽复用：未分配记录仍保留原 `$OBJECT_ID`（样本 `deleted.mft` 的 FRS 39/43 均为
  `in_use = False` 但仍有 GUID），而序列号语义本身存在不确定（`MFT.py:1025-1031` 注释）。
  因此"同一 GUID 在两个时间点出现"不能直接等价于"同一个文件对象一直存在"。
- 本工具没有实现"GUID → 记录号"的反查（§1.6），也没有实现跨卷对象 ID 迁移的自动比对。

### 4.4 证据完整性（这会影响"是否发生过迁移"的判断）

- MoveTable 有"已刷新"标志：`is_log_flushed()` 只读 flags 最低位（`MoveTable.py:87-90`、
  `13`）。样本 `tracking_4kn.bin` 的 flags = 0（未刷新），`tracking_3_move_to.bin` 与
  `tracking_512_large.log` 的 flags = 1（已刷新）。未刷新时，日志可能不包含完整事件流。
- `get_expansion_data()`（`MoveTable.py:97-101`）在全部样本中返回全零，即**无法用它界定
  日志覆盖的索引区间**。
- 解析器会跳过 `UNUSED` 类型项（`MoveTable.py:16`、`365-373`）；但遇到不认识的类型码会在
  构造时抛 `NotImplementedError`（`MoveTable.py:167-168`），`log_entries()` 不捕获，
  生成器会**整体中断**。一条坏项就能截断后续全部证据，扫描结果必须记为"不完整"。
- 扇区大小靠启发式猜测：读偏移 512 处的 16 字节，全零判为 4096，否则判为 512
  （`MoveTable.py:329-340`）。样本恰好都能猜对（`test_cases.py:3545-3559` 断言了这一点），
  但这是猜测，正式分析应显式传入 `sector_size`。
- `tracking_3_move_to.bin` 已刷新且共 39 个扇区，但**没有任何移动通知项**
  （实测非 `UNUSED` 项为 0）。"日志里没有记录"≠"没有发生过移动"。

### 4.5 时间语义的边界

- MoveTable 事件时间只有秒级 32 位值，只能给出 ~429.5 s 区间（§2.3）。
- GUID 时间只在版本 1 时存在，版本 4 为 `None`（§2.2）。
- USN v4 无时间（§2.4）。
- `$LogFile` 无时间字段（§2.4）。
- 无卷创建/格式化时间（§2.6）。

---

## 5. 为什么"对象生成时刻"不能直接替代"文件创建时刻"

### 5.1 代码层面的理由

1. `get_timestamp()` 取的是 **GUID 生成时刻**。GUID 可以在文件创建之前批量生成（同一次
   `UuidCreateSequential` 缓存刷新会产出多个共享同一时间戳的 GUID），也可以从别处复制/
   迁移而来；代码没有任何"该 GUID 属于本次创建"的校验。
2. 版本 4 时根本没有时间（`Attributes.py:506-511`）。
3. `$OBJECT_ID` 可以被替换；USN 里虽有 `OBJECT_ID_CHANGE` 原因码，但本工具不提供
   "变更前后"的值（§4.3）。
4. 即使 GUID 时间正确，它描述的是"对象"的生命周期起点，而"文件"的 `$SI C` 描述的是
   当前记录/名称的创建时刻；重命名、硬链接、跨卷迁移都不改变对象 ID，但会改变名称与位置。

因此报告正确写法：
> `$OBJECT_ID` GUID `…` 的生成时间为 T，早于/晚于 `$SI`/`$FN` 记录的创建时间 T′；
> 两者分别对应"对象"与"文件"两个层面，T 不能作为 T′ 的替代或上界。

### 5.2 样本实测（`test_data/nist-hacking-case.mft`，52 条记录带 `$OBJECT_ID`）

- 51 条为版本 1（带时间），1 条为版本 4（`$Volume`，无时间）。
- 这 51 个时间戳只落在 **7 个**不同的值上：

| GUID 时间戳 | 记录数 |
|---|---|
| 2004-08-20 15:05:09.158068 | 18 |
| 2004-08-20 15:05:09.158066 | 14 |
| 2004-08-19 23:04:14.625774 | 6 |
| 2004-08-27 15:12:16.019472 | 6 |
| 2004-08-25 15:56:09.999172 | 3 |
| 2004-08-25 15:56:09.999174 | 3 |
| 2004-08-26 15:05:21.970092 | 1 |

前两组仅相差 2 µs，却各覆盖 18 个和 14 个不同的文件（`UNINST~1.EXE`、`Links`、
`mirc.exe`、`readme.txt` 等）。如果把这些时间当成"文件创建时间"，就会得到
"几十个不相关文件在同一微秒被创建"的荒谬结论——这正说明它是**GUID 生成批次的时刻**。

- 按差值（`$SI C` − GUID 时间）统计（n = 51）：GUID 时间早于文件创建时间 25 例、
  晚于 26 例；绝对值 ≤ 5 s 的只有 2 例，≤ 60 s 的 4 例。差值范围从 −90,450,915.158 s
  （FRS 10166 `tweakui.exe`：`$SI C` = 2001-10-08 17:49:54.000000，GUID 时间 =
  2004-08-20 15:05:09.158068，即 GUID 比 C 晚约 2.9 年）到 +1,360.186 s
  （FRS 11072 `channels.txt`，即 §5.3 的例子）。
  这个"两边都有"的分布说明二者**没有固定的先后关系**，任何方向的替代都不成立。

### 5.3 单个文件的完整对照（FRS 11072，`/Program Files/mIRC/channels/channels.txt`）

```
$SI  M = A = E = 2004-08-20 19:28:13.740772
$SI  C          = 2004-08-20 15:27:49.343622
$SI  USN        = 0
$FN  C = E      = 2004-08-20 15:27:49.343622
$FN  parent     = 562949953432381
$OBJECT_ID GUID = 53d29f0e-f2ba-11d8-b0f9-0010a4933e09
GUID 时间        = 2004-08-20 15:05:09.158068   （比 $SI/$FN C 早 22 分 40.186 秒）
FRS LSN         = 31832129
```

同一 GUID 在 `test_cases.py:400-412` 的单元测试里被断言为
"timestamp == 2004-08-20 15:05:09.158068"。也就是说，测试本身只验证了
"GUID 解码结果可复现"，**没有**验证它与文件创建时间的关系。

### 5.4 删除记录仍保留对象 ID（`test_data/deleted.mft`）

| FRS | 是否在用 | `$OBJECT_ID` GUID 时间 | 路径 | `$SI C` |
|---|---|---|---|---|
| 39 | 否 | 2019-01-24 21:22:31.625146 | `/1` | 2019-01-24 21:27:24.107008 |
| 43 | 否 | 2019-01-24 21:22:31.625148 | `/1/2` | 2019-01-24 21:27:27.482162 |

两例 GUID 时间都比 `$SI C` 早约 5 分钟，且两条记录的对象 ID 时间相差仅 2 µs。
未分配记录里保留旧 GUID 是预期行为，但这也意味着：**看到 GUID 不代表文件此刻存在**，
看到路径也不代表路径当时有效（`build_full_paths` 只是按当前 `$MFT` 重建，
`ntfs_parser:380` 对日志模式还专门标注 "likely wrong if the file was deleted later"）。

### 5.5 MoveTable 中的"生成时间"与"事件时间"是两个量

| 样本 | 日志项数 | GUID 时间范围 | 条目事件时间范围 | 差（最早事件 − 最早 GUID） |
|---|---|---|---|---|
| `tracking_4kn.bin` | 9 | 2020-04-03 11:46:38 – 12:16:07 | 2020-04-03 13:01:33.264076 – 13:08:42.760806 | 1 小时 14 分 55 秒 |
| `tracking_512_large.log` | 30 | 2020-07-25 12:29:49 – 2020-08-02 20:20:15 | 2020-08-02 23:52:37.361664 – 23:59:46.858394 | 8 天 11 小时 22 分 48 秒 |

两组样本里 GUID 时间都**严格早于**事件时间带，且提前量从 1 小时到 8 天不等。
这不能证明"GUID 时间一定是创建时间"，只能证明它与"移动事件时间"无关；
把 `GUID timestamps` 与 `Timestamp (range)` 放在同一段输出里（`ntfs_parser:931-939`）
很容易被误读为同一事件的两种表述。

### 5.6 输出层面的误读风险（报告口径必须避开）

| 位置 | 现状 | 风险 |
|---|---|---|
| `--mft` CSV 列名 `$OBJID timestamp`（`ntfs_parser:85`） | 单列时间，与 `$SI C`、`$FN C` 并列 | 极易被当成第四种"文件时间" |
| `--mft` 取值逻辑（`ntfs_parser:105-118`、`156-159`） | 只取第一个 `$OBJECT_ID`，版本 4 时为空 | 列空不等于无对象 ID |
| `--log` 输出 `$OBJECT_ID` 段（`ntfs_parser:569-574`） | 打印 "Timestamp:" | 同样暗示文件时间 |
| `--move` 输出（`ntfs_parser:913-939`） | 依次打印 Object ID、DROID、Machine ID、Birth DROID、GUID timestamps、Timestamp (range) | 未标注哪一个是生成时间、哪一个是事件区间 |
| `format_timestamp(None)`（`ntfs_parser:10-15`） | 统一输出 `N/A` | 无法区分"版本 4"、"值非法"、"字段截断" |
| `--all-mft`（`ntfs_parser:863-881`） | 主卷与各快照合并输出 | 不同 source 的同一 GUID 会被当成多份证据 |

---

## 6. 建议的证据陈述模板

对单条记录：

> $MFT 记录号 N（序列号 S，LSN L）名为 P。
> `$OBJECT_ID` GUID G（版本 v；若 v=1，node 字段为 MAC M0，GUID 生成时刻 T_g）。
> 文件时间：`$SI` C/M/A/E = …，`$FN` C/M/A/E = …（两者是否一致：是/否）。
> 对象标识与文件时间的对应关系：**未建立**；T_g 与 `$SI C` 相差 Δ（方向：早/晚）。
> 该 GUID 是否为记录的当前身份：**未验证**（本工具未解析 `$ObjId` 索引）。

对 MoveTable：

> 日志头部卷 GUID V_h，Machine ID M_h，刷新标志 F（0 = 未刷新，覆盖不完整）。
> 条目 i：Object ID G，DROID 卷 V_d / 对象 O_d，Birth DROID 卷 V_b / 对象 O_b，
> 事件时间区间 [t, t + 429.4967295 s]。
> 可断言：G 与 O_d、O_b 在字节层面相同；V_d ≠ V_h = V_b。
> **不可断言**：V_d / V_b 对应哪块物理卷、哪次挂载、哪个 $MFT 记录。

对卷：

> 引导扇区序列号 S_v（`BootSector.py:121`）、GPT 分区唯一 GUID G_p 或 MBR 磁盘签名 G_m、
> `$Volume` 记录的对象 ID G_vol、卷标 N。四者是不同层面的标签，**不互相等价**。

---

## 7. 复现方法

样本目录视为不可信数据，脚本另放目录，用 `-I` 运行以免从当前目录导入同名模块：

```bash
# 1) 扫描 $MFT 中的 $OBJECT_ID 及其 GUID 时间（对照 §5.2）
python3 -I - <<'EOF'
import sys; sys.path.insert(0, '/path/to/repo')
from dfir_ntfs import MFT, Attributes
mft = MFT.MasterFileTableParser(open('/path/to/repo/test_data/nist-hacking-case.mft', 'rb'))
for fr in mft.file_records():
    for a in fr.attributes():
        if type(a) is MFT.AttributeRecordResident and a.type_code == Attributes.ATTR_TYPE_OBJECT_ID:
            v = a.value_decoded()
            print(fr.get_master_file_table_number(), fr.is_in_use(),
                  v.get_object_id(), v.get_object_id().version,
                  v.get_timestamp(), len(v.get_extra_data()))
EOF

# 2) MoveTable：GUID 时间 vs 事件时间带（对照 §5.5）
python3 -I - <<'EOF'
import sys; sys.path.insert(0, '/path/to/repo')
from dfir_ntfs import MoveTable
p = MoveTable.MoveTableParser(open('/path/to/repo/test_data/tracking_512_large.log', 'rb'))
print(p.get_header().get_extended_header().volume_object_id, p.get_header().is_log_flushed())
for e in p.log_entries():
    print(e.get_object_id(), e.get_guid_timestamps()[0], e.get_timestamp())
EOF
```

仓库自带测试只覆盖解码本身，不覆盖语义：
`test_cases.py:400-412`（16 字节 `$OBJECT_ID` 的 GUID 与时间）、
`test_cases.py:3379-3559`（MoveTable 头部、扇区、日志项与字段值）。
运行 `python3 -m pytest test_cases.py -k "object_id or movetable"` 通过，
但这并不构成"对象生成时刻 = 文件创建时刻"或"卷归属可判定"的任何证据。
