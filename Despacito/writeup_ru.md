# Despacito writeup

## Задание

Дан crypto-таск `D3Spacito` на `100` очков с коротким описанием:

```text
lowkey despacito....
```

В архиве есть:

- `ques.py`
- `output.txt`

Формат флага:

```text
THEM?!CTF{...}
```

## Смотрим исходник

Скрипт очень маленький:

```python
from Crypto.Cipher import DES
import base64
from FLAG import flag

def pad(plaintext):
    while len(plaintext) % 8 != 0:
        plaintext += b"*"
    return plaintext

def enc(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(plaintext))

key = bytes.fromhex("E1E1E1E1F0F0F0F0")
plaintext = pad(flag)
print(enc(plaintext, key).decode())
```

То есть схема здесь такая:

- шифр: `DES`
- режим: `ECB`
- ключ: `E1E1E1E1F0F0F0F0`
- паддинг: символы `*` до длины, кратной 8
- результат кодируется в base64

В `output.txt` лежит:

```text
T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=
```

## Почему ключ сразу выглядит подозрительно

Первое, что бросается в глаза, это структура ключа:

```text
E1 E1 E1 E1 F0 F0 F0 F0
```

Для случайного DES-ключа это слишком красиво.
Когда DES-ключ имеет такой повторяющийся вид, первым делом стоит проверить weak keys.

У DES есть четыре классических weak key, для которых шифрование и дешифрование совпадают:

```text
01 01 01 01 01 01 01 01
FE FE FE FE FE FE FE FE
1F 1F 1F 1F 0E 0E 0E 0E
E0 E0 E0 E0 F1 F1 F1 F1
```

Выданный ключ очень близок к последнему:

```text
E1 E1 E1 E1 F0 F0 F0 F0
E0 E0 E0 E0 F1 F1 F1 F1
```

Разница только в младшем бите каждого байта.

## Трюк с parity bits

В этом и состоит вся задача.

В DES каждый байт 64-битного внешнего ключа содержит:

- 7 настоящих ключевых бит
- 1 parity bit

Младший бит каждого байта - это именно бит четности.

При построении внутреннего 56-битного ключа DES выбрасывает эти 8 бит четности через `PC-1`.

Следовательно, две строки:

```text
E1E1E1E1F0F0F0F0
E0E0E0E0F1F1F1F1
```

дают **один и тот же эффективный DES-ключ**.

То есть выданный нам ключ не просто "рядом" с weak key.
Это и есть weak key, только замаскированный parity bits.

## Почему это ломает шифрование

Для weak key у DES выполняется свойство:

```text
E_k(E_k(P)) = P
```

Или эквивалентно:

```text
E_k = D_k
```

Значит, если шифртекст был получен как:

```text
c = E_k(flag)
```

то восстановить plaintext можно обычным:

```text
flag = D_k(c)
```

А поскольку ключ weak, эта операция по сути совпадает с самим шифрованием.

## Получение флага

Нужно base64-декодировать строку и расшифровать ее через `DES-ECB` тем же ключом.

Локально я проверил это через OpenSSL с legacy provider:

```bash
openssl enc -provider legacy -provider default \
  -des-ecb -d \
  -K E1E1E1E1F0F0F0F0 \
  -nosalt -nopad -a \
  -in output.txt
```

Результат:

```text
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```

## Минимальный solve script

```python
from base64 import b64decode
from Crypto.Cipher import DES

key = bytes.fromhex("E1E1E1E1F0F0F0F0")
ct = b64decode("T/tGpZNyHdhnf1oxwRmMPFcLiH//AfZdTpmYdp8daU0=")

pt = DES.new(key, DES.MODE_ECB).decrypt(ct)
print(pt.decode())
```

## В чем суть задачи

Здесь не нужно "ломать DES" в каком-то сложном смысле.
Нужно всего лишь:

1. заметить подозрительно красивый DES-ключ,
2. вспомнить, что у DES есть parity bits,
3. понять, что данный ключ является parity-bit twin для weak key,
4. просто расшифровать шифртекст.

То есть основная идея задачи в том, что разные 64-битные представления ключа могут сводиться к одному и тому же 56-битному effective key после отброса битов четности.

## Итоговый флаг

```text
THEM?!CTF{D3S_4774K_W3S_AW3S0M3}
```
