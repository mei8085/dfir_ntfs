# exFAT：连续簇声明（NoFatChain / 目录项）与分配位图给出的文件来源线索为何不同

分析对象：`dfir_ntfs/addons/exFAT.py`（1301 行）、`fat_parser`（125 行），并与 `dfir_ntfs/addons/FAT.py`、`dfir_ntfs/MFT.py` 对照。
分析方式：只读解析 `test_data/` 中的 5 个 exFAT 卷镜像（`exfat_win.raw.gz`、`win_exfat_7.raw.gz`、`exfat_lin_part.raw.gz`、`exfat_encrypted.raw.gz`、`exfat_orphan.raw.gz`），所有数值均由脚本对解析结果重新统计得到，未修改仓库任何文件。

---

## 0. 结论摘要

1. **"能读出来的字节"与"能归属于该目录项的字节"是两个集合，且解析器只保证前者。**
   `FileSystemParser.read_chain()`（`exFAT.py:1138`）只做"把簇拼成缓冲区 + 按 DataLength 截断"，**从不查询分配位图**；`Bitmap.is_allocated()`（`exFAT.py:1030`）只在 `walk()` 里用于决定要不要递归进目录（`exFAT.py:1231`），不参与文件数据的读取与归属。因此任何调用 `read_chain()` 得到的字节，都可能是别的文件、系统文件或已释放簇的内容。
2. **DataLength 是唯一的长度闸门，ValidDataLength 完全不参与读取。** `valid_data_length` 被解析、被放进 `FileEntry`（`exFAT.py:700/883/936`），但全仓库没有一处读取路径使用它（`grep valid_data_length` 只命中解析与测试）。所以 VDL=0 的文件照样能读出 4096 字节；VDL 之后的字节不是"当前文件内容"，只是簇内残留/填充/密文。
3. **删除条目的校验和必然失效，不是篡改证据。** 条目集校验和覆盖包含 in-use 位的字节，清除 in-use 位必然改变校验和：实测 `exfat_win` 根目录 599 个在用条目集，清除 in-use 位后 **599/599** 校验和不再匹配。解析器因此对删除条目**跳过**校验（`exFAT.py:822/829`），也就无法用校验和区分"完整删除"与"字段被改过的删除"。
4. **FAT 与位图不一致是常态，二者都不能单独作为"被占用"的证据。** `exfat_win`：位图空闲但 FAT 非零 **145** 簇，位图占用但 FAT 为 0 **714** 簇；`exfat_encrypted` 分别为 28 / 7。NoFatChain 文件（700 个、6315 簇）中有 **5601** 簇的 FAT 项仍非零，其中 5583 个还指向合法簇号——这些是历史链残留，不是当前文件的链。
5. **删除条目的簇在当前常被在用文件占据。** `exfat_win` 4 个带簇的删除条目中 3 个（`/1.bin`→簇22、`/333.bin`→簇417、`/555.bin`→簇680）指向在用文件正占用的簇；被删目录 `/0` 指向的簇 21 就是**活根目录链的第 116 个簇**。`exfat_encrypted` 9 个带簇的删除条目中 8 个（声明 32768 字节）与在用的 `*.PFILE` 共享簇。

---

## 1. 卷读取路径

### 1.1 引导区来源可以悄悄改变全部几何参数

`FileSystemParser.__init__`（`exFAT.py:1083-1109`）依次尝试 `0`、`12*512`、`12*4096` 三个引导区偏移，第一个通过校验的就采用，并把 `backup_used` 置为"是否用了备份"（`exFAT.py:1109`）。簇大小、簇堆偏移、根目录簇、FAT 位置、分配位图位置全部由该引导区导出。

`win_exfat_7.raw.gz` 的实例：

| 引导区 | 校验和 | 扇区/簇 | 卷序列号 | 卷标志 | percent_in_use |
|---|---|---|---|---|---|
| main (0) | **坏**（存 0x80cdcbe0 / 算 0xb743bcf8） | — | 0x947889e1 | (F,F,F,F) | — |
| backup512 | OK | 512 / 8 | 0x947889e1 | (F,F,F,F) | 0 |
| backup4096 | 错（非 EXFAT） | — | — | — | — |

即：这张卷"可读"本身依赖于备份引导区，主引导区已损坏。若只看主引导区或只信 `fs.br` 而不记录 `backup_used`，得到的"卷上有什么"是不可比的。同理 `exfat_win` 的主/备引导区 `percent_in_use` 分别是 54 和 0，而实际计算值为 54.1%。

### 1.2 卷边界只在调用者传入 `volume_size` 时才生效

`exFAT.py:1187` 的越界检查条件是 `self.volume_size is not None`。而 `fat_parser` 的两处构造（`fat_parser:75`、`fat_parser:82`）**都不传 volume_size**，测试里也大量使用 `exFAT.FileSystemParser(f)`。结果是：读取上限只有 `last_valid_cluster`（`exFAT.py:1123`，= 引导区 cluster_count + 1），**不含镜像/分区实际长度**。对镜像文件而言，超出卷尾的"簇"会读到镜像里紧随其后的内容（例如相邻分区），被当成该卷的文件数据返回而不报错。

### 1.3 卷状态标志被解析但从不影响判读

`get_volumeflags()`（`exFAT.py:392-402`）返回 `(active_fat, volume_dirty, media_failure, clear_to_zero)`，但只有 `active_fat` 被使用（`exFAT.py:1119`，用于选择 FAT 与位图 id）。`volume_dirty`（卷未干净卸载）、`media_failure`（曾发生介质错误）、`clear_to_zero`（簇堆正在/曾被清零）在解析与 `fat_parser` 输出中都不出现。`clear_to_zero` 直接决定"未分配簇里是否还可能有残留"，是本报告中归因推理的前提条件之一，却被丢弃。

此外 `percent_in_use`（`exFAT.py:435`）被 `calculate_checksum()` 排除在校验范围外（`exFAT.py:510` 跳过 106/107/112 字节），且实测会失真（`win_exfat_7` 存 0、实算 0.3%；`exfat_orphan` 存 0、实算 0.3%）。它不能作为分配状态的旁证。

---

## 2. 目录解析路径

### 2.1 条目的三个关键字段来自哪里

`DirectoryEntries.entries()`（`exFAT.py:755`）按 32 字节滑窗扫描：

- `DE_FILE`（0x05，`exFAT.py:800`）给出 `secondary_count`、属性、时间戳、集合校验和；要求 `2 <= secondary_count <= 64`（`exFAT.py:802`）。
- 第二个条目必须是 `DE_STREAM_EXTENSION`（`exFAT.py:857`），从其中解出（`exFAT.py:883`）：
  `efs_padding_size, name_length, name_hash, efs_header_size, valid_data_length, first_cluster, data_length`
- `FileEntry.size = data_length`，`FileEntry.valid_data_length = valid_data_length`（`exFAT.py:928/936`）。

只有 `allocation_possible` 位被强制检查（`exFAT.py:873`）；`no_fat_chain` 位被原样透传（`exFAT.py:871/929`）成为 `FileEntry.no_fat_chain`，它决定 `read_chain()` 走"连续簇"还是"FAT 链"两条完全不同的路径。

### 2.2 删除条目的校验和不可用

```python
# exFAT.py:822
# Now, validate the entries. No checksum validation is performed against deleted entries.
# exFAT.py:829
if (not is_deleted) and set_checksum != EntrySetChecksum(...):
    pos += 32; continue
```

这不是实现偷懒，而是 exFAT 的校验和定义（`EntrySetChecksum`，`exFAT.py:267`）覆盖条目集内除偏移 2..3 以外的全部字节，**包括每个条目的类型字节（含 in-use 位）**。在 `exfat_win` 根目录上做的对照实验：

- 在用的 599 个条目集：校验和全部匹配（`in_use/match = 599/599`）。
- 把每个条的 in-use 位清零后重新计算：**599/599 不再匹配**。
- 卷上实际存在的删除条目：5/5、26/26、1/1（分别为 `exfat_win`、`exfat_encrypted`、`exfat_orphan`）校验和都不匹配。

因此：
- 对**在用**条目，校验和是有效的结构完整性标记（篡改 `first_cluster`/`data_length` 会破坏它）。
- 对**删除**条目，校验和恒失效，**无法**用它证明剩余字段（尤其 `first_cluster`、`data_length`）仍是删除时的原值。任何基于删除条目 `first_cluster` 的内容归因都必须单独论证。

### 2.3 若干关键字段根本不做合理性校验

用构造的条目集直接喂 `DirectoryEntries`，以下"不可能"的组合都被**接受**并产出 `FileEntry`：

| 构造 | 解析结果 |
|---|---|
| `valid_data_length=9999, data_length=10` | `('a.txt', size=10, vdl=9999)` |
| `data_length=0xFFFFFFFF, first_cluster=50` | `size=4294967295`（4 GiB） |
| `data_length=0, first_cluster=77` | `size=0, first=77`（统计为空、却带簇号） |
| `first_cluster=0, data_length>0`（见 6.5 实测） | 接受，读取返回空 |

对照 NTFS 侧：`MFT.py:433-434` 明确校验 `valid_data_length <= file_size <= allocated_length`，exFAT 侧没有对应检查。后果：
- `valid_data_length > data_length` 不会被发现，`read_chain` 又不用 VDL，两者矛盾被无声吞掉。
- `data_length` 可以大到远超卷容量，且 NoFatChain 时 `read_chain` 会一路读到 `last_valid_cluster` 为止（实测见 3.2）。
- `name_hash`（`exFAT.py:883`）解析后从未使用，即**文件名与内容之间没有被任何校验绑定**；用它对删除条目做重命名/错配检测的能力被白白丢弃。

### 2.4 `walk()` 里的分配判断只影响"要不要进目录"

`exFAT.py:1231-1253`：

```python
is_allocated = self.bm.is_allocated(dir_entry.first_cluster)
if is_allocated is None: continue                      # 簇号非法
if dir_entry.is_directory:
    if (not scan_reallocated) and dir_entry.is_deleted and is_allocated:
        reallocated_directories.add(...)               # 删目录但簇被占用：默认不递归
        continue
    visited_directories.add(...)
    new_buf = self.read_chain(dir_entry.first_cluster, dir_entry.size, dir_entry.no_fat_chain)
```

即：

- **在用目录**不论首簇是否被位图标记为占用，一律递归读取。
- **删除目录**只有在首簇被标记为占用时才被"跳过"（默认模式下），被跳过的目录被记录进 `reallocated_directories`，`scan_reallocated=True` 时再以 `<Orphan directory N>` 前缀重新解析（`exFAT.py:1284-1298`）。
- 文件数据本身**从不检查分配状态**。

对"删除目录里仍标记为在用"的子项，`fat_parser` 的用法提示（`fat_parser:55-58`）已经承认这个陷阱，但只覆盖这一种情形。

---

## 3. "可读字节"的三条互不等价来源

`read_chain(first_cluster, file_size, no_fat_chain)`（`exFAT.py:1138`）实际有三种行为：

### 3.1 连续簇模式（`no_fat_chain=True`）

```python
while remaining_size > 0:
    if curr_cluster > self.last_valid_cluster: break     # exFAT.py:1159
    clusters.append(curr_cluster); curr_cluster += 1; remaining_size -= self.cluster_size
```

簇数 = `ceil(file_size / cluster_size)`，从 `first_cluster` 顺序向后。**不看 FAT，不看位图。** 若 `file_size` 被伪造成 0xFFFFFFFF，就会一直读到卷尾：

```
win_exfat_7: read_chain(50, 0xFFFFFFFF, no_fat_chain=True)
  -> 5 963 776 字节（1456 簇），正好止于 last_valid_cluster=1505，无异常
```

### 3.2 FAT 链模式（`no_fat_chain=False`）

`FAT.chain()`（`exFAT.py:646`）沿 FAT 前进，遇到以下任一情况停止：`EOC`、`BAD`（追加一个 `None`）、`0`（"空文件"标记）、`1`（保留）、成环（`exFAT.py:669`）、越界。`None` 簇在读取时**用零填充**（`exFAT.py:1177-1179`）。

两个直接后果：

1. **链比 DataLength 短时静默返回短缓冲区。** `read_chain(21, 100000, no_fat_chain=False)` 返回 **512 字节**，不抛异常、不告警；调用者只有比较 `len(buf) != size` 才能发现。
2. **链比 DataLength 长时，超出部分被截断丢弃**（`exFAT.py:1201`）。`exfat_encrypted` 的删除条目 `aaaa…aa.PFILE`：`data_length=4112`，FAT 链 2 簇（8192 字节容量），实际只返回 4112 字节，另有 4080 字节"可读但被丢弃"。
3. **零填充字节是解析器制造的**，不是卷上内容；把它当作"文件里有一段全零"是错误归因。

### 3.3 目录缓冲区

目录用同一函数读取（`exFAT.py:1258/1290`），所以目录也会出现 3.1/3.2 的全部问题；目录的 `DirectoryEntries` 扫描到 `DE_END_OF_DIRECTORY`(0x00) 或 `DE_INVALID`(0x80) 为止（`exFAT.py:768-775`），其后的簇内字节不参与解析，但仍"可读"。实测 5 张卷的在用目录 **0** 个在结束标记之后含非零字节，即这些样本的目录尾空是干净的——这是观测结果，不是保证。

### 3.4 位图读取本身也会越界抛错

`Bitmap.is_allocated()`（`exFAT.py:1030-1045`）对 `cluster<2` 或 `cluster>last_valid_cluster` 返回 `None`，但对"簇号在范围内、位图缓冲区却不够长"的情况会抛 `IndexError`：

```
Bitmap(b'\xff'*8, last_valid_cluster=66)
  is_allocated(65) -> True
  is_allocated(66) -> IndexError: index out of range
```

位图缓冲区由 `read_chain()` 读整条 FAT 链得到（`exFAT.py:1132`，不传 size），而声明长度在 `AllocationBitmapEntry.size`（`exFAT.py:974`）。实测 `exfat_win` 位图：链给出 1536 字节、声明 1504 字节、恰好覆盖 12033 个簇所需 1504 字节——样本上没问题；但位图被截断的镜像会让 `walk()` 直接抛出未捕获的 `IndexError`。**"分配状态未知"与"分配状态未知导致的崩溃"需要在报告里区分。**

---

## 4. 区分"可读取"与"可归属"

### 4.1 归属成立的四个条件（缺一不可）

一个簇里的字节可以归属于某个目录项，当且仅当：

| # | 条件 | 解析器是否提供 | 证据来源 |
|---|---|---|---|
| A | 条目集结构有效（在用条目校验和匹配；删除条目至少字段自洽） | 在用：是（`exFAT.py:829`）；删除：否 | 2.2 |
| B | 该簇在**分配位图**中标记为占用 | 是（`bm.is_allocated`），但读取路径不用 | `exFAT.py:1030` |
| C | 该簇**没有**被其他在用条目或系统文件（根目录链、位图自身、大小写表）同时声明 | 否（需调用者自行建立占用表） | 本报告脚本 |
| D | 该簇位于该条目 DataLength 所覆盖的范围内（且不越过 ValidDataLength 才算"内容") | DataLength：是（截断）；VDL：**否** | `exFAT.py:1201` |

`exfat_win` 上按 A–D 统计（仅统计可读的非目录在用条目）：

```
在用非目录条目 401 个；可读范围 3 104 768 字节
  其中"独占 + 位图已分配" 3 104 768 字节
  其中"与其他条目共享 或 位图为空" 0 字节
```

即：**在"当前在用、未被删除"的常态下，可读集合与可归属集合可以重合**；一旦跨到删除条目或非常规条目，两者立刻分离。下面逐项给分离的证据。

### 4.2 分离实例

**(a) 删除条目指向在用文件的簇 —— `exfat_win`**

| 删除条目 | first_cluster | DataLength | 位图 | 当前占用者 | `read_chain` 实际返回 |
|---|---|---|---|---|---|
| `/1.bin` | 22 | 1 | 已分配 | `/fragmented_file_and_long_name_l…l.txt` | `b't'`（该长文件第 1 字节） |
| `/333.bin` | 417 | 3 | 已分配 | `/598/0.bin`（size=1） | `b'0\x00\x00'` |
| `/555.bin` | 680 | 3 | 已分配 | `/598/1.bin`（size=1） | `b'1\x00\x00'` |
| `/0`（目录） | 21 | 512 | 已分配 | **活根目录链的第 116 个簇** | 根目录字节；可解析出 `llll…l.txt` |
| `/Текстовый документ.txt` | 0 | 0 | — | — | `b''` |

- `/333.bin` 的 3 字节里有 2 字节超出了当前占用者的 DataLength（1 字节），即**连"别人的文件内容"都算不上，是别人的簇内尾部空**。
- `/1.bin` 的 FAT 残留给出 `22 → 6469 → … → 6516`，链长 49 簇 = **25 088 字节**，且**每一簇都由同一个在用长文件占用**（尾簇 FAT=EOC）。也就是说，如果按 FAT 链而不是按 DataLength 读取，删除条目 `/1.bin` 会吐出**另一个在用文件的 25 KB 内容**。这是"连续簇声明与 FAT 残留给出不同来源线索"的最直接例子：同一条删除项，Path/DataLength 说它只有 1 字节，FAT 说它是一条 49 簇的链，而位图+交叉占用表说这条链全属于别人。
- `/0` 是最强的一例：删除目录的 cluster 21 就是当前活根目录 FAT 链的最后一个簇（根目录链 116 簇，`br.get_firstclusterofrootdirectory()=17`）。"恢复删除目录 /0"实际是"把当前根目录的一个簇当成旧目录读"。

**(b) 加密卷上的原地替换 —— `exfat_encrypted`**

Windows EFS-in-exFAT 的落盘形态：`X.bin` 被删除（in-use 位清零），同簇上出现 `X.bin.PFILE`（在用，DataLength=4096+EFS头+填充，VDL=4096 或 0）。实测：

```
9 个带簇的删除条目中 8 个与对应 *.PFILE 共享首簇（声明 32768 字节）
例如 删除 /encrypted_dir/1.bin  first=12  ->  在用 /encrypted_dir/1.bin.PFILE first=12
     读出的 4096 字节 = EFS 头(0x00100000…)+密文，不是原 .bin 明文
```

对 `1.bin` 这类删除条目：DataLength 与 VDL 都是 0/4096 量级（条目里 VDL=0），内容却是 EFS 元数据 + 密文。**只有在标明"该簇现由 PFILE 占用"之后，这些字节才能被正确解释**；否则会把密文当成"已恢复的原文"上报。

**(c) 位图为空但簇仍可解析 —— `win_exfat_7`**

| 条目 | 类型 | first_cluster | 位图 | 簇内容 |
|---|---|---|---|---|
| `/1` | 删除目录 | 7 | **空闲** | 非零 63 字节，仍可解析出条目 `2`、`3` |
| `/1/2` | **在用**目录 | 8 | **空闲** | 全零 |
| `/1/3` | **在用**目录 | 9 | **空闲** | 全零 |

`walk()` 对 `/1` 的簇 7 照常递归（`is_deleted and is_allocated` 为假，不进 `reallocated_directories`），于是 `/1/2`、`/1/3` 以"在用目录"身份出现在 `fat_parser` 的 CSV 里（`Is deleted=N`），而它们的簇在位图上明确是空闲的。这是"目录项声明"与"分配位图声明"互相矛盾的活样本：位图说这些簇可被覆盖，目录项说它们是两个在用目录。

---

## 5. 有效长度（ValidDataLength）如何限制归因

### 5.1 解析器完全不使用 VDL

`valid_data_length` 的完整使用面：

```
exFAT.py:700   出现在 FileEntry 字段表
exFAT.py:883   从 Stream Extension 解出
exFAT.py:726/732/936   在 ExpandPath 与 yield 之间搬运
```

`read_chain()` 里没有任何一处引用它。因此：

- VDL 之后的字节**一律被当作文件内容返回**。
- "文件当前真实内容"的边界在解析器内部无表示，只能由调用者用 `(first_cluster, size, valid_data_length, no_fat_chain)` 自行重建。

实测 `exfat_encrypted` 的 `/usual_dir/0.bin.PFILE`：

```
size = 4096, valid_data_length = 0, first_cluster = 30
read_chain(...) -> 4096 字节，其中 434 字节非零（EFS 头 + 填充）
```

按 exFAT 语义，VDL=0 表示**没有有效用户数据**；读出的 4096 字节属于"已分配但未写入有效数据"的区域。若把它当作"文件内容"上报，就会凭空制造出一份 4 KB 的"证据"。对照组 `/encrypted_dir/1.bin.PFILE`：`size=4112, vdl=4112`，此时 4112 字节全部可读且覆盖 VDL 范围。

### 5.2 尾部空（tail slack）：可读但不是内容

对 `size % cluster_size != 0` 的在用文件，最后一个簇中 `[size : cluster_size)` 的字节可读、但不在 DataLength 内：

| 卷 | 有尾空的在用文件 | 尾空总字节 | 其中含非零字节的文件数 | 非零内容性质 |
|---|---|---|---|---|
| `exfat_win` | 400 | 203 664 | 0 | 全零 |
| `win_exfat_7` | 1 | 4 089 | 0 | 全零 |
| `exfat_lin_part` | 2 | 8 184 | 0 | 全零 |
| `exfat_encrypted` | 12 | 48 176 | 9 | 每文件 476–494 字节，EFS 填充/密文 |
| `exfat_orphan` | 0 | 0 | — | — |

`exfat_win` 的 400 个文件尾空全为零，说明这些样本在该区域被清零过（与 `clear_to_zero` 语义一致，但卷标志位上没记录）；`exfat_encrypted` 的 9 个文件尾空含非零密文——同一"尾空"概念在两张卷上的证据价值完全相反。**只看 len(buf) 而不看 size/VDL，无法区分这两种情况。**

### 5.3 VDL 与 DataLength 的矛盾不被发现

构造 `vdl > data_length` 的在用条目集，`DirectoryEntries` 照常产出 `FileEntry`（见 2.3）。真实的 exFAT 写路径不会产生这种条目，但被篡改/被历史版本写坏的条目会；解析器对此没有防护，也没有把矛盾作为告警暴露。

---

## 6. 历史释放如何限制归因

### 6.1 位图与 FAT 是两套独立的证据，且经常不一致

对全部簇同时查询位图与 FAT：

| 卷 | (位图占用, FAT 非零) | (位图占用, FAT=0) | (位图空闲, FAT 非零) | (都为空闲) |
|---|---|---|---|---|
| `exfat_win` | 5800 | **714** | **145** | 5373 |
| `win_exfat_7` | 4 | 1 | 0 | 1499 |
| `exfat_lin_part` | 4 | 14 | 0 | 16078 |
| `exfat_encrypted` | 22 | 7 | **28** | 8103 |
| `exfat_orphan` | 4 | 10 | 0 | 4062 |

- **位图占用、FAT=0（714 簇 / 14 簇 / …）**：典型的 NoFatChain 布局。此时若用 FAT 判断"是否被占用"，会把在用数据判成空闲。
- **位图空闲、FAT 非零（145 簇 / 28 簇）**：簇已释放但 FAT 项未清。若用 FAT 判断"是否被占用"，会把可被覆盖的旧数据判成在用。`exfat_win` 的样本 `FAT[6467]=6468`、`FAT[6517]=6518 → 6518 → 6519 → …` 是成段的旧链残留。

**结论：判定"簇是否被当前文件系统占用"必须以位图为准；FAT 只能用于重建"曾经是谁的链"，且必须假定它可能已过时。**

### 6.2 NoFatChain 文件的 FAT 残留会给出错误的"下一簇"

NoFatChain 文件只声明首簇和长度，FAT 中对应位置按规范可以是任意值/零。实测这些位置的 FAT 值分布：

| 卷 | NoFatChain 在用文件的簇数 | FAT 项非零 | 其中指向合法簇号 |
|---|---|---|---|
| `exfat_win` | 6315 | **5601** | 5583 |
| `exfat_encrypted` | 23 | **16** | 16 |
| `win_exfat_7` / `exfat_lin_part` / `exfat_orphan` | 3 / 13 / 0 | 0 | 0 |

其中还有**跨文件**的假指针（FAT 项指向另一个在用文件的簇）：`exfat_win` 1 例、`exfat_encrypted` 9 例。以 `exfat_encrypted` 为例：`/encrypted_dir/1.bin.PFILE` 的首簇 12 的 `FAT[12]=0`，按 FAT 读只得到 4096 字节（声明 4112，**静默短读**、丢掉 16 字节 EFS 尾）；而该文件自己占用的第二个簇 13 的 `FAT[13]=14`，簇 14 属于 `/encrypted_dir/3.bin.PFILE`——任何把簇 13 当作链首的处理都会走进另一个文件的密文。实测连续声明读 4112 字节、FAT 链读 4096 字节，内容恰在 4096 处分叉。

`exfat_win` 的删除目录 `/0`（first=21）的另一面也说明这点：它的 FAT 项是 EOC，而 cluster 21 实际位于活根目录链的**中部**（链上第 116/116 个）—— FAT 项"看起来像 EOC 的合法链尾"完全不妨碍该簇属于别人。

### 6.3 释放后的残留可读性没有保证

位图空闲的簇里是否还有内容，取决于实现（是否清零）：

| 卷 | 位图空闲簇数 | 其中含非零字节 | 例 |
|---|---|---|---|
| `exfat_win` | 5518 | 0 | — |
| `exfat_orphan` | 4062 | 0 | — |
| `exfat_encrypted` | 8131 | **1** | 簇 32：298 字节非零，UTF-16 风格文本残留 `G U J R d …`，FAT[32]=33→34→EOC，**无任何条目引用** |

`exfat_encrypted` 簇 32 是"历史释放"最纯粹的证据形态：位图说空闲、没有任何目录项指向它、FAT 残留仍把它串进一条已死的 3 簇链、内容是可疑的旧文件名残片。它**只能**被标记为"未归属残留"，不能归给任何文件；反过来，`exfat_win`、`exfat_orphan` 的空闲簇全为零，说明这两个样本被清零过——**"空闲簇里没东西"不是卷的性质，是本次样本的性质**，换一张卷结论就会反转。

同时，已释放的簇可能被**立即**重新分配：`exfat_encrypted` 里删除条目 `aaaa…aa`（first=29，DataLength=4112）按连续簇声明应覆盖簇 29、30；实测簇 29 已被清零且位图空闲，簇 30 已属于在用的 `/usual_dir/0.bin.PFILE`（位图占用）。同一个删除条目，一半的声明范围已经不存在、另一半属于别人。这就是文档标题所说的"连续簇声明与分配位图给出不同来源线索"。

### 6.4 目录项与位图的三种矛盾态（对应 `walk()` 的处理）

| 情形 | 位图 | 解析器行为 | 归因风险 |
|---|---|---|---|
| 在用条目 → 空闲簇 | 空闲 | 照常读取、照常递归（`walk` 只对"删除目录"做位图判断） | 把"已无主的簇"当成在用文件内容（`win_exfat_7` 的 `/1/2`、`/1/3`） |
| 删除条目 → 占用簇 | 占用 | 默认跳过目录递归，记入 `reallocated_directories`；`scan_reallocated=True` 时以 `<Orphan directory N>` 重解析 | 把当前占用者的数据当成旧文件内容（`exfat_win` 的 `/0`、`/1.bin`） |
| 删除条目 → 空闲簇 | 空闲 | 直接读取、直接递归 | 读到的可能是零填充、可能是已被部分覆盖的旧数据，两种无法从缓冲区区分 |

第 2 行还叠加了另一个启发式：`reallocated_directories_metadata` 在同一首簇有多个删除目录条目时，**按 mtime 选"最新"的那个**来取 size 和 no_fat_chain（`exFAT.py:1244-1251`）。删除条目的 mtime 与其余字段同样无法用校验和背书（2.2），因此"用哪个条目的元数据去读哪个簇"这一步本身是可被伪造的推断。

### 6.5 "有 DataLength 但没有簇"的删除条目

`exfat_encrypted` 的 `/System Volume Information/EFS0.LOG` 有 **10** 个删除条目声明了 512/1536/2048 字节，但 `first_cluster=0`，`read_chain` 返回 `b''`。这类条目的可读字节是 0，声明的长度是历史长度的残影——两者都不构成内容证据。此类情形共 17/26（`no extent or empty`）。

---

## 7. 工具输出层面的缺口（决定了报告读者会看到什么）

`fat_parser` 的 exFAT 分支只输出 9 列（`fat_parser:109/122`）：

```
Is deleted, Is directory, Path, M/A/C 时间戳, TZ, File size, Is encrypted
```

缺失且对归因至关重要的字段：

- `first_cluster`、`no_fat_chain`（无法判断"连续声明"还是"FAT 链"）
- `valid_data_length`（无法区分"有效内容"与"已分配未写")
- **分配位图状态**（无法区分"在位图里占用"与"已释放但仍可读"）
- `EFS 头大小`、`padding size`、`name_hash`（加密文件与名称绑定的判读依据）
- 卷标志 `volume_dirty` / `media_failure` / `clear_to_zero`、`backup_used`

`File size` 一列实际是 **DataLength**，而对 VDL=0 的加密文件（如 `/usual_dir/0.bin.PFILE`）这一列显示 4096，读者会自然把它当"文件内容 4096 字节"。工具自带的警告（`fat_parser:55-58`）只说明"删除目录可能包含被标记为在用的子项"，没有覆盖本报告 3、4、5、6 节的全部歧义。

---

## 8. 判读规则（建议写进取证报告的最小集）

对每个"可读"的字节区间，按顺序回答四个问题，任一为"否"就不能把字节归给该条目：

1. **结构**：条目集在用且校验和匹配吗？若是删除条目，`first_cluster` / `data_length` / `no_fat_chain` 有没有独立旁证（位图、FAT 残留、同簇其它条目、文件内容自洽性）？——删除条目的校验和**恒失效**（2.2），不能当作旁证。
2. **分配**：`bm.is_allocated(cluster)` 对区间内**每一簇**为 True 吗？——位图是占用状态的权威；FAT 与它不一致时（6.1）以位图为准，并记录差异。
3. **独占**：区间内每一簇有没有被其他在用条目、根目录链、分配位图自身、大小写表同时声明？——`exfat_win` 中 3 个删除条目和 `/0` 都是反例（4.2a）。
4. **长度**：区间在 DataLength 之内吗？读出的字节里，哪些落在 `[valid_data_length, size)`？——VDL 不参与读取（5.1），必须显式切分：`[0, vdl)` 才是"有效内容"，`[vdl, size)` 是"已分配未写"，`[size, cluster_end)` 是尾部空。

并在卷级别记录三个前提：

- 实际使用的是主引导区还是备份（`backup_used`），因为几何参数可能不同（1.1）。
- 解析时的 `volume_size` 是否给定、FAT/位图是否被截断（1.2、3.4）——未给定则"可读"可能越出卷界。
- 卷标志（尤其 `clear_to_zero`）与是否观察到空闲簇被清零（1.3、6.3）——它决定"空闲簇残留"这条线索在本题卷上是否成立。

一句话概括：**目录项的连续簇声明回答"这条元数据说内容在哪、有多长"，FAT 回答"这条簇链曾经怎么串起来"，分配位图回答"现在这一簇归不归文件系统管"。三者交叉一致时，可读字节才等于可归属字节；三者不一致时要记录的是三份相互矛盾的线索，而不是取其中任意一份当结论。**

---

## 附录 A：复现方法

所有结论都可用下列最小脚本在仓库根目录复核（只读，不写卷）：

```python
import gzip, sys
sys.path.insert(0, '.')
from dfir_ntfs.addons import exFAT

f = gzip.open('test_data/exfat_win.raw.gz', 'rb')
fs = exFAT.FileSystemParser(f, 0)
print('backup_used =', fs.backup_used, 'cluster =', fs.cluster_size,
      'last_valid_cluster =', fs.last_valid_cluster)

# 位图 vs FAT 不一致计数
fb = bf = 0
for c in range(2, fs.last_valid_cluster + 1):
    v = fs.fat.get_element(c)
    if v and not fs.bm.is_allocated(c): fb += 1        # 位图空闲、FAT 非零
    if fs.bm.is_allocated(c) and not v: bf += 1        # 位图占用、FAT 为 0
print('bitmap-free but FAT nonzero =', fb, '; bitmap-allocated but FAT zero =', bf)

# 删除条目：DataLength 截断后的读取 vs FAT 链
for e in fs.walk():
    if type(e) is exFAT.FileEntry and e.is_deleted and e.first_cluster >= 2:
        print(e.name, 'first =', e.first_cluster, 'size =', e.size,
              'nofat =', e.no_fat_chain, 'alloc =', fs.bm.is_allocated(e.first_cluster))
        print('  declared-extent read:', repr(fs.read_chain(e.first_cluster, e.size, e.no_fat_chain)[:16]))
        if not e.no_fat_chain:
            print('  FAT chain:', fs.fat.chain(e.first_cluster)[:8],
                  'capacity =', len(fs.fat.chain(e.first_cluster)) * fs.cluster_size)
```

关键观测对照（本报告引用值）：

| 观测 | 命令/位置 | 结果 |
|---|---|---|
| 清除 in-use 位是否必然破坏校验和 | 4.2、2.2 | 599/599 |
| 删除条目共享在用途簇 | 4.2a | 3/4（`exfat_win`）、8/9（`exfat_encrypted`） |
| VDL=0 仍读出 4096 字节 | 5.1 | `/usual_dir/0.bin.PFILE`，434 字节非零 |
| 链短于 DataLength 时静默短读 | 3.2 | `read_chain(21, 100000)` → 512 字节 |
| NoFatChain 伪 DataLength 读到卷尾 | 3.1 | 5 963 776 字节 |
| 空闲簇残留 | 6.3 | 仅 `exfat_encrypted` 簇 32（298 字节） |

## 附录 B：代码位置索引

| 主题 | 位置 |
|---|---|
| 引导区尝试与 `backup_used` | `exFAT.py:1097-1109` |
| 引导区校验和（跳过 106/107/112） | `exFAT.py:505-520` |
| 卷标志解析 | `exFAT.py:392-402` |
| 卷边界检查（依赖 `volume_size`） | `exFAT.py:1187` |
| 条目集解析、`secondary_count` | `exFAT.py:800-936` |
| 删除条目跳过校验和 | `exFAT.py:822, 829` |
| `valid_data_length` / `first_cluster` / `data_length` 解出 | `exFAT.py:883` |
| Stream 标志位（`AllocationPossible` / `NoFatChain`） | `exFAT.py:259-265, 871-875` |
| FAT 链遍历与停止条件 | `exFAT.py:646-689` |
| `read_chain` 三条路径 | `exFAT.py:1138-1201` |
| 坏簇零填充 | `exFAT.py:1177-1179` |
| 位图查询 | `exFAT.py:1030-1045` |
| `walk` 中的分配判断 | `exFAT.py:1231-1253` |
| 重分配目录的元数据启发式 | `exFAT.py:1244-1251, 1284-1298` |
| 工具输出列 | `fat_parser:109, 122` |
| 工具警告文字 | `fat_parser:55-58` |
| NTFS 侧 VDL 校验（对照） | `MFT.py:433-434` |
| FAT 侧无 VDL 字段（对照） | `FAT.py:1086-1092, 1100` |
