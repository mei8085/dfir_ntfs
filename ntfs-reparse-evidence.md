# NTFS 重解析点（$REPARSE_POINT）取证证据边界报告

分析对象：本仓库 dfir_ntfs 代码（`dfir_ntfs/Attributes.py`、`dfir_ntfs/MFT.py`、
`dfir_ntfs/USN.py`、`ntfs_parser`）及样本 `test_data/rp.bin`（一个含重解析点的
FILE record segment，FRS）。

核心结论：**现有代码只解析重解析点的通用头部（标签、数据长度、第三方 GUID、原始载荷
缓冲区），不解析任何标签专属载荷，也不维护标签值到名称的映射表。** 因此工具本身不会、
也不能给出任何"重定向去向"的结论；载荷内的路径只能由分析人员按已知标签结构手工解读，
未知标签必须原样保留字节。

---

## 1. 代码实际解析了什么

### 1.1 通用重解析点头部 —— 可靠解读

`dfir_ntfs/Attributes.py:959-990` 的 `ReparsePoint` 类只暴露 4 个访问器：

| 方法 | 偏移/来源 | 含义 | 证据等级 |
|---|---|---|---|
| `get_reparse_tag()` | `value[0:4]`，小端 DWORD | 重解析标签（tag） | 字段可可靠读出；但代码不解释其具体含义 |
| `get_reparse_data_length()` | `value[4:6]`，WORD | 载荷（reparse data）字节数 | 可靠 |
| `is_reparse_tag_microsoft()` | tag 的最高位 `0x80000000` | 该标签是否属 Microsoft 命名空间 | 可靠（仅一位判断，非标签识别） |
| `get_reparse_guid()` | `value[8:24]`，仅第三方 | 第三方重解析点的 GUID | 仅当 Microsoft 位为 0 时返回，否则返回 `None` |
| `get_reparse_buffer()` | 见下 | 标签专属载荷的原始字节切片 | 长度可靠，**内容不做任何解释** |

载荷切片的两种起点（`Attributes.py:984-990`），对应 Windows
`REPARSE_DATA_BUFFER` 的两种布局：

- Microsoft 标签：`value[8 : 8 + data_length]`（头部 8 字节：tag + data length +
  2 字节保留字）。
- 第三方标签：`value[24 : 24 + data_length]`（头部 24 字节：8 字节通用头 +
  16 字节 GUID）。

`print_information()`（`Attributes.py:992-997`）也只打印标签十六进制值、
"is Microsoft" 布尔值和数据长度，**不打印任何路径**。

### 1.2 代码明确不做的事（证据边界）

1. **没有标签字典。** 全仓库不存在 `0xA000000C`（符号链接）、`0xA0000003`
   （挂载点/junction）等任何具体标签常量；`grep` 到的 `TAG_*` 常量
   （`Attributes.py:114-119`）是 $STANDARD_INFORMATION 的"已知文件夹"标签，
   与重解析点无关。工具对标签的全部认知就是最高位是不是 Microsoft。
2. **不解析载荷结构。** 没有 SubstituteName/PrintName、偏移/长度字段、
   符号链接 flags 等任何解析逻辑；`get_reparse_buffer()` 返回的是未解释的字节。
3. **`ntfs_parser` 的 CSV 输出完全不含重解析列。** `process_mft()`
   （`ntfs_parser:79-197`）的表头与逐字段输出中没有 tag、没有目标路径，
   重解析属性即使存在也不会被写进 CSV。
4. **单元测试只做哈希比对。** `test_cases.py:335-354` 对样本仅断言
   "是 Microsoft 标签"，并对载荷缓冲区做 MD5 校验
   （`a8ac63b71e1af29121c6d3c3c438926b`），从不解读载荷内容——这与工具
   "保留原始字节、不替分析员下结论"的定位一致。

### 1.3 周边可佐证"存在重解析点"的字段（仅证明存在，不证明去向）

- $STANDARD_INFORMATION 的文件属性位 `FILE_ATTR_REPARSE_POINT = 0x0400`
  （`Attributes.py:69,96`）。样本中 SI 属性 = `0x420`，即
  `ARCHIVE | REPARSE_POINT`，可可靠证明该文件被标记为重解析点。
- SI 中的信任等级 `get_trust_level()`（`Attributes.py:302-305`，取 extra flags
  的 bit4-5；常量 `TRUST_LEVEL_1=1` 普通用户、`TRUST_LEVEL_2=2` 内核/管理员，
  见 `Attributes.py:122-124`）。这是重解析点的安全属性，与目标路径无关。
- USN 变更原因 `USN_REASON_REPARSE_POINT_CHANGE = 0x00100000`
  （`USN.py:29,54`）：只能证明重解析点发生过变更，不含目标信息。

---

## 2. 哪些"目标路径"可可靠解读，哪些只能保留原始字节

### 2.1 可由现有字段可靠读出的内容（无需推测）

以下信息直接来自代码访问器，属一手、可复核证据：

- 重解析标签的**原始数值**（如样本 `0xA000000C`）与数据长度；
- Microsoft / 第三方命名空间归属（最高位）；
- 第三方标签的 GUID；
- 完整载荷的原始字节（按 data_length 定界，边界明确）；
- SI 中的 REPARSE_POINT 属性位与信任等级。

### 2.2 载荷内路径：仅在标签已知且结构匹配时，可由分析员手工解读

工具不做这一步，但对**已知 Microsoft 标签**，分析员可依据公开的
`REPARSE_DATA_BUFFER` 结构在保留原始字节的同时做条件性解读：

- `IO_REPARSE_TAG_SYMLINK (0xA000000C)` 与 `IO_REPARSE_TAG_MOUNT_POINT
  (0xA0000003)` 的载荷都含两对"偏移+长度"定位的 UTF-16LE 字符串：
  **SubstituteName（实际重定向目标）** 与 **PrintName（仅用于显示）**；
  符号链接另有 4 字节 flags（bit0 = 相对链接）。
- 本次样本 `rp.bin` 手工解码结果（标签 `0xA000000C`，flags=1 相对链接）：
  SubstituteName 与 PrintName 均为 `target.txt`；该 FRS 的 $FILE_NAME 为
  `link.txt`。
- **即便结构匹配，解读仍有边界：**
  - 相对符号链接的 `target.txt` 是相对字符串，真实落地路径需结合该链接所在
    目录拼接，载荷本身不包含绝对去向；
  - 挂载点的 SubstituteName 常以 NT 命名空间前缀 `\??\` 出现，前缀处理与
    盘符映射属于解释层，应在报告中单独标注，不能与原始字符串混写。

### 2.3 只能保留原始字节的情形

- **任何工具标签字典之外的标签值**：代码既不识别标签名，也不保证载荷布局，
  禁止套用符号链接/挂载点结构去"猜"路径。应记录：tag 原始值、Microsoft 位、
  （第三方）GUID、data_length、载荷 hex，并明确标注"标签未识别，目标未知"。
- **第三方（非 Microsoft）标签**：只有 GUID 可可靠命名；其载荷结构由对应
  厂商的文件系统过滤驱动定义，无公开结构时不得解释为路径。
- **长度/越界异常的载荷**：`get_reparse_buffer()` 完全信任头部给出的
  data_length，代码不做边界校验；若 data_length 超出属性实际值，切片结果
  可能短于声明长度，此时只能保留实际取到的字节并记录异常。
- **已知标签但字段偏移越界或 UTF-16 解码失败**：停止字符串解读，回退为
  原始字节，不得用替换字符拼凑出"看似有效"的路径。

---

## 3. 路径展示 vs. 实际重定向：证据区分

报告必须把三类"名字"分开陈述，任何一个都不能单独当作文件去向：

| 证据 | 来源 | 证明什么 | 不证明什么 |
|---|---|---|---|
| 链接自身的显示名 | $FILE_NAME（样本 `link.txt`） | 重解析点在目录中的名称 | 与重定向目标无关 |
| **PrintName** | 重解析载荷内 | 资源管理器/`dir` 展示给用户看的目标文本 | **不证明** I/O 实际跳转位置；它可以是任意易读字符串，甚至可与真实目标不一致 |
| **SubstituteName** | 重解析载荷内 | 解析路径时实际替换使用的目标（真正的重定向证据） | 相对目标不含完整路径；需结合父目录与命名空间前缀才能落地 |

关键取证原则：

1. **PrintName 是展示证据，SubstituteName 才是重定向证据。** 二者是载荷中
   两个独立、各自带偏移/长度的字段，值可以不同。报告引用目标时必须注明引用的
   是哪一个；仅出现 PrintName 时，结论只能写"显示为 X"，不能写"指向 X"。
2. **未知标签不得解释为已确认的文件去向。** 标签未识别时，载荷里即便出现
   可打印的 UTF-16 片段，也只能称为"载荷中可见的字符串"，不能称为目标路径；
   因为没有标签结构保证该片段处于 SubstituteName 偏移上。
3. **工具输出的边界就是结论的边界。** 本仓库工具的确定性输出止于
   tag 数值/长度/GUID/原始载荷，以及 SI 的 REPARSE_POINT 标记与信任等级；
   任何路径级结论都是分析员依据已知标签结构做的二次解读，应在报告中与
   工具原始输出分栏呈现，并附原始字节（或其哈希，如样本的
   MD5 `a8ac63b71e1af29121c6d3c3c438926b`）以备复核。
4. **存在性与去向分开下结论。** SI 的 `0x0400` 属性位、USN 的
   `USN_REASON_REPARSE_POINT_CHANGE` 只证明重解析点存在或被改动，
   不能作为"文件被重定向到某处"的证据。

---

## 4. 对本样本（test_data/rp.bin）的证据化描述示例

- FRS 文件名（$FILE_NAME）：`link.txt`；SI 文件属性 `0x420`
  = ARCHIVE | REPARSE_POINT（可靠，工具直出）。
- $REPARSE_POINT：tag = `0xA000000C`（Microsoft 命名空间；工具仅给出数值，
  标签名"SYMLINK"属分析员对照公开文档的标注），data length = 52，
  SI trust level = 0。
- 载荷（52 字节，MD5 `a8ac63b71e1af29121c6d3c3c438926b`，与单元测试一致）
  按符号链接结构手工解读：flags=1（相对链接）；PrintName = `target.txt`
  （显示文本）；SubstituteName = `target.txt`（实际替换目标，相对路径，
  完整去向需结合 `link.txt` 所在目录解析）。
- 原始载荷 hex 应随报告归档：
  `1400140000001400010000007400610072006700650074002e007400780074`
  `007400610072006700650074002e00740078007400`。
