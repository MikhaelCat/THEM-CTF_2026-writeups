# 🦀? writeup

## Задание

Дан файл:

```text
crabbymonty.exe
```

Категория: `reverse`

Описание:

```text
Time for some rusty business
```

Формат флага:

```text
THEM?!CTF{...}
```

## Итоговый флаг

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```

## Общая идея решения

Это не обычная проверка строки внутри нативного кода Rust. Внутри `crabbymonty.exe` спрятан XOR-обфусцированный `Python 3.12 .pyc`, а уже в нем находится настоящая функция проверки флага.

Поэтому путь решения такой:

1. понять, что бинарь написан на Rust;
2. заметить в `.rdata` подозрительный большой blob;
3. увидеть, что он декодируется простым `xor 0x69`;
4. получить из него валидный `pyc`;
5. дизассемблировать байткод;
6. восстановить `check_flag()`;
7. обратить преобразование и получить исходную passphrase.

## Первичный анализ бинаря

Сначала смотрим тип файла:

```bash
file crabbymonty.exe
```

Результат:

```text
PE32+ executable for MS Windows 6.00 (console), x86-64, 5 sections
```

То есть это 64-битный PE под Windows.

### Импорты и общий профиль

Полезно посмотреть заголовки:

```bash
objdump -x crabbymonty.exe
```

Из важного:

- entrypoint: `0x1400284b0`
- есть обычные winapi-импорты;
- присутствуют типичные Rust-строки паники;
- в строках есть `rust_rev.pdb`.

По строкам очень быстро видно, что это именно Rust:

```text
called `Result::unwrap()` on an `Err` value
/rustc/.../library\std\src\...
mainRUST_MIN_STACK
rust_panic
```

Это уже намекает, что в дизасме будет довольно много рантайма и мусора, а полезную логику лучше искать не по `main`, а по константам и ссылкам на данные.

## Попытка динамики

Логично сначала попробовать просто запустить бинарь под `wine`, но здесь это не дало полезного поведения:

```text
[FATAL] CRITICAL EXCEPTION: 0x80040154
Unhandled memory fault ...
Subsystem initialization failed. Core dumped.
```

То есть полноценная динамика под Linux оказалась не самым удобным путем. Поэтому дальше быстрее идти статикой.

## Поиск нестандартных строк и данных

Обычные строки вида `Correct`, `Wrong`, `Access granted` почти ничего не дают. Но в `.rdata` обнаруживается очень странный большой участок данных.

Ключевой фрагмент дизасма рядом с ним:

```asm
140001765: leaq 0x29e9d(%rip), %rbx   # 0x14002b609
...
140001780: xorb $0x69, %r15b
...
14000179c: cmpq $0xc2b, %r14
```

Это очень важное место. Что тут видно:

- есть указатель на blob по адресу `0x14002b609`;
- цикл длиной `0xc2b` байт;
- каждый байт XOR-ится с `0x69`.

Такой паттерн очень похож на “зашифрованный встроенный файл”.

## Извлечение blob из `.rdata`

Можно достать данные напрямую из PE. Я использовал небольшой скрипт на Python с `pefile`.

```python
import pefile
from pathlib import Path

pe = pefile.PE("crabbymonty.exe")
rva = 0x2b609
size = 0xc2b

for s in pe.sections:
    va = s.VirtualAddress
    vs = s.Misc_VirtualSize
    raw = s.PointerToRawData
    if va <= rva < va + vs:
        off = raw + (rva - va)
        data = pe.__data__[off:off + size]
        break
else:
    raise RuntimeError("blob not found")

decoded = bytes(b ^ 0x69 for b in data)
Path("chall.pyc").write_bytes(decoded)
print(decoded[:16].hex())
```

После декодирования начало файла стало таким:

```text
cb0d0d0a000000003c50ee6906080000
```

Это уже очень похоже на заголовок `pyc`.

## Почему это точно Python bytecode

Если посмотреть первые байты после заголовка, видно marshal-код объекта:

```text
e3 00 00 00 ...
```

А при загрузке через `xdis` получается корректная информация:

- версия: `Python 3.12.0`
- filename внутри bytecode: `chall.py`
- размер исходника: `2054 bytes`

То есть внутри Rust-бинаря реально лежит спрятанный `chall.pyc`.

## Дизассемблирование `.pyc`

Локальный системный `dis` у меня был на более новой версии Python, поэтому для аккуратного разбора удобно использовать `uv` или `xdis`.

Например:

```bash
uv run --python 3.12 python - <<'PY'
import marshal, dis
from pathlib import Path

b = Path("chall.pyc").read_bytes()
co = marshal.loads(b[16:])
dis.dis(co)
for c in co.co_consts:
    if hasattr(c, "co_name"):
        print("SUBCODE:", c.co_name)
        dis.dis(c)
PY
```

После этого уже виден модуль и функция `check_flag`.

## Восстановление логики `check_flag`

По байткоду функция восстанавливается практически в прямой Python:

```python
import base64

def check_flag(user_input):
    target = [
        241, 250, 126, 93, 101, 32, 92, 189, 201, 144, 156, 157,
        61, 197, 242, 125, 64, 195, 80, 221, 116, 218, 238, 61,
        89, 80, 154, 29, 13, 138, 66, 253, 209, 112, 64, 93,
        69, 211, 66, 189, 41, 42, 242, 157, 29, 79, 204, 125,
        161, 28, 162, 221, 85, 95, 192, 61, 184, 252, 246, 29,
        109, 63, 170, 253, 48, 220, 178, 93, 165, 47, 180, 189,
        8, 188, 198, 157, 125, 255, 40, 125, 129, 138, 142, 221,
        181, 239, 36, 61, 153, 106, 194, 29, 77, 143, 156, 253,
        17, 74, 146, 93, 133, 140, 130, 189, 104, 60, 38, 157,
        93, 122, 26, 125, 225, 63, 240, 221, 149, 90, 22, 61,
        248, 252, 54, 29, 173, 63, 248, 253, 113, 255, 224, 93,
        229, 26, 226, 189, 72, 188, 10, 157, 189, 207, 108, 125,
        193, 138, 252, 221, 244, 204, 106, 61, 216, 124, 6, 29,
        141, 186, 194, 253, 81, 127, 192, 93, 197, 154, 212, 189,
        169, 60, 110, 157, 156, 108, 70, 125, 32, 28, 34, 221,
        213, 95, 64, 61, 57, 234, 118, 29, 236, 44, 56, 253,
        177, 131, 62, 14
    ]

    hex_str = user_input.encode().hex()
    spaced = " ".join(hex_str[i:i+2] for i in range(0, len(hex_str), 2))

    std_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    cust_alpha = b"HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/"

    b64 = base64.b64encode(spaced.encode())
    custom_b64 = b64.translate(bytes.maketrans(std_alpha, cust_alpha)).decode()

    _pavel = True
    _damwan = (_pavel << 3) | (_pavel << 2) | _pavel
    _tao = (_pavel << 3) - _pavel
    _felon = (_pavel << 1) | _pavel
    _them = (_pavel << 8) | (_pavel << 7) | (_pavel << 5) | (_pavel << 2)

    encoded = []
    for i, c in enumerate(custom_b64):
        poly_key = (
            _damwan * (i ** _felon) +
            _felon * (i ** (_pavel << _pavel)) +
            _tao * i +
            _them
        ) & 255
        encoded.append(ord(c) ^ poly_key)

    if len(encoded) != len(target):
        return False
    return encoded == target
```

## Упрощение констант

Переменные с шуточными именами только мешают читать код. Поскольку `_pavel = True`, а в Python `True == 1`, можно упростить:

- `_damwan = (1 << 3) | (1 << 2) | 1 = 8 | 4 | 1 = 13`
- `_tao = (1 << 3) - 1 = 8 - 1 = 7`
- `_felon = (1 << 1) | 1 = 2 | 1 = 3`
- `_them = (1 << 8) | (1 << 7) | (1 << 5) | (1 << 2) = 256 | 128 | 32 | 4 = 420`
- `(_pavel << _pavel) = (1 << 1) = 2`

Тогда полином становится сильно проще:

```python
poly_key = (13 * (i ** 3) + 3 * (i ** 2) + 7 * i + 420) & 255
```

Итоговая схема проверки:

1. взять ввод пользователя;
2. перевести в байты;
3. представить как hex-строку;
4. вставить пробел между каждыми двумя hex-символами;
5. закодировать получившуюся строку в base64;
6. заменить стандартный алфавит base64 на кастомный;
7. для каждого символа XOR с полиномиальным ключом от индекса;
8. сравнить с `target`.

## Как обратить эту проверку

Проверка полностью обратима.

Если в прямом направлении было:

```text
user_input
 -> hex
 -> hex с пробелами
 -> base64
 -> custom alphabet
 -> xor с poly_key
 -> target
```

То в обратном нужно сделать:

```text
target
 -> xor с poly_key
 -> custom base64 string
 -> вернуть стандартный alphabet
 -> base64 decode
 -> убрать пробелы
 -> bytes.fromhex(...)
 -> исходная строка
```

## Решающий скрипт

Полный solve:

```python
import base64

target = [
    241, 250, 126, 93, 101, 32, 92, 189, 201, 144, 156, 157,
    61, 197, 242, 125, 64, 195, 80, 221, 116, 218, 238, 61,
    89, 80, 154, 29, 13, 138, 66, 253, 209, 112, 64, 93,
    69, 211, 66, 189, 41, 42, 242, 157, 29, 79, 204, 125,
    161, 28, 162, 221, 85, 95, 192, 61, 184, 252, 246, 29,
    109, 63, 170, 253, 48, 220, 178, 93, 165, 47, 180, 189,
    8, 188, 198, 157, 125, 255, 40, 125, 129, 138, 142, 221,
    181, 239, 36, 61, 153, 106, 194, 29, 77, 143, 156, 253,
    17, 74, 146, 93, 133, 140, 130, 189, 104, 60, 38, 157,
    93, 122, 26, 125, 225, 63, 240, 221, 149, 90, 22, 61,
    248, 252, 54, 29, 173, 63, 248, 253, 113, 255, 224, 93,
    229, 26, 226, 189, 72, 188, 10, 157, 189, 207, 108, 125,
    193, 138, 252, 221, 244, 204, 106, 61, 216, 124, 6, 29,
    141, 186, 194, 253, 81, 127, 192, 93, 197, 154, 212, 189,
    169, 60, 110, 157, 156, 108, 70, 125, 32, 28, 34, 221,
    213, 95, 64, 61, 57, 234, 118, 29, 236, 44, 56, 253,
    177, 131, 62, 14
]

std_alpha = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
cust_alpha = b"HIJKLMNOPQRSTUVWXYZABCDEFGhijklmnopqrstuvwxyzabcdefg6789012345+/"

reverse_table = bytes.maketrans(cust_alpha, std_alpha)

custom_b64 = bytes(
    t ^ ((13 * (i ** 3) + 3 * (i ** 2) + 7 * i + 420) & 0xff)
    for i, t in enumerate(target)
)

std_b64 = custom_b64.translate(reverse_table)
spaced_hex = base64.b64decode(std_b64).decode()
hex_str = spaced_hex.replace(" ", "")
flag = bytes.fromhex(hex_str).decode()

print(flag)
```

Вывод:

```text
THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}
```

## Локальная верификация

Я дополнительно перепроверил результат прямым прогоном той же логики:

```python
assert check_flag("THEM?!CTF{a_sn4k3_4nd_a_cr4b_c4n_b3_g00d_fr13nd5}")
```

Проверка проходит, значит passphrase восстановлена корректно.

## Почему задача хорошая

Это приятный reverse не на “сложную крипту”, а на комбинацию наблюдательности и аккуратного восстановления пайплайна:

- снаружи это Rust-бинарь;
- внутри спрятан Python bytecode;
- поверх него есть легкая обфускация XOR;
- сама проверка строится из нескольких обратимых преобразований.

Самая важная мысль здесь: как только виден встроенный blob и простой `xor 0x69`, задача почти перестает быть “реверсом Rust” и превращается в “достань и обрати Python-проверку”.
