# Good9 writeup

## Задание

Дан таск `Good9`, к которому приложен Android APK:

- `nightnight.apk`

Внутри APK лежат:

- `classes.dex`
- `classes2.dex`
- `lib/arm64-v8a/libsilence.so`
- `lib/x86_64/libsilence.so`
- два подозрительных asset-файла:
  - `assets/218a844439e58d15043399c3d9be4ca009ebeb51c237c33d4315771af5973c6c`
  - `assets/b86e8f6ffb52c768dd5b27bde4e53176d58552012a252e11e923406a095cd6d6`

Уже по структуре видно, что это многоступенчатый mobile-rev таск:

- Java/Kotlin-обвязка
- основная логика в native `libsilence.so`
- скрытый payload, лежащий в assets

## Общая идея

Это приложение специально разбито на несколько слоев.

Первый DEX **не** содержит прямой логики получения флага.
Вместо этого приложение:

1. загружает native-библиотеку
2. выводит промежуточный ключ
3. расшифровывает скрытый DEX из assets
4. динамически грузит этот DEX
5. смешивает Java-side и native-side секреты
6. только после этого получает финальный ключ для расшифровки флага

То есть это не одна уязвимость, а полноценный chained reverse pipeline.

## Java recon через JADX

Если открыть APK в JADX, быстро находятся ключевые точки:

- `FlagApplication` загружает `libsilence.so`
- `Night.loadKey(AssetManager)` вызывается на старте
- по нажатию кнопки идет вызов `Night.prepareVM(getClassLoader(), getAssets())`
- возвращается объект, реализующий интерфейс `VM`
- в `vm.getFlag(...)` передается `Night.getKey()`
- существует native-метод `Night.bridge(byte[])`

Критичное наблюдение здесь такое:

- `Night.getKey()` возвращает **не финальный ключ флага**
- это лишь промежуточный `StageKey`, которым открывается следующий слой

Если этого не заметить, очень легко застрять, пытаясь расшифровать всё напрямую из первого найденного секрета.

## Вход в native: `libsilence.so`

Дальше основная работа уходит в `libsilence.so`.

Лучший первый pivot - `JNI_OnLoad`.

Трассировка от него показывает:

- ранние anti-debug проверки
- runtime-дешифровку строк
- динамически собранный `RegisterNatives`
- native-обработчики для `loadKey`, `prepareVM`, `bridge` и фейкового VM-пути

Это значит, что по одним exported symbols задачу не решить.
Часть важных JNI-имен вообще проявляется только после runtime-дешифровки.

## Runtime string decoder

Одна из первых полезных побед - найти функцию дешифровки строк.

Через нее можно восстановить такие строки, как:

- `lab/nightjar/darkness/Night`
- `lab/nightjar/darkness/Night$NightVM`
- `loadKey`
- `prepareVM`
- `bridge`
- `getFlag`
- `dalvik/system/InMemoryDexClassLoader`
- `lab.hiddenvm.RealVM`

Уже на этом этапе становится понятна общая архитектура:

- в основном APK сидит фейковая видимая VM
- настоящая логика живет в скрытом secondary DEX

## Anti-debug поведение

`libsilence.so` специально затрудняет динамический анализ.

Внутри есть несколько классических anti-debug проверок:

- `ptrace(PTRACE_TRACEME)`
- чтение `TracerPid` из `/proc/self/status`
- поиск Frida/Gadget по `/proc/self/maps`

Неприятный нюанс в том, что эти проверки не обязаны сразу убивать приложение.
Вместо этого они могут "травить" внутреннее состояние.

То есть плохой bypass может не вызвать crash, но сломает дальнейшие результаты:

- получится неверный `StageKey`
- неправильно расшифруется hidden DEX
- сломается финальный `bridgeKey`

Именно поэтому таск неприятнее обычного `if (debugger) exit`.

## Этап 1: получение StageKey

Первый реальный секрет получается через native-пайплайн:

```text
seed asset -> pre_transform -> custom VM -> post_transform -> StageKey
```

40-байтный asset:

```text
assets/b86e8f6ffb52c768dd5b27bde4e53176d58552012a252e11e923406a095cd6d6
```

подается именно в этот процесс.

### `pre_transform`

На этом шаге seed проходит через смесь из:

- S-box lookup
- циклических сдвигов
- перестановок байтов
- round constants
- антидебажного poison state

Результат становится начальным состоянием памяти/регистров для VM.

### Native VM

Дальше VM дешифрует свой bytecode из `.rodata`, восстанавливает dispatch table и исполняет кастомный instruction set поверх этого состояния.

Основные intended pain points:

- bytecode зашифрован
- таблица хендлеров обфусцирована
- семантика VM не читается по строкам

Нормальный путь решения тут либо:

- восстановить хендлеры и написать Python-эмулятор
- либо аккуратно снять anti-debug, прогнать один запуск и дампнуть состояние после VM

### `post_transform`

После завершения VM идет финальная обработка, которая сжимает состояние в 40-байтную ASCII-подобную строку.

Это и есть `StageKey`.

Но это всё еще **не финальный ключ флага**.

## Этап 2: hidden DEX

Большой asset:

```text
assets/218a844439e58d15043399c3d9be4ca009ebeb51c237c33d4315771af5973c6c
```

является зашифрованным payload.

Его формат:

```text
salt[16] || iv[16] || ciphertext
```

Из найденного `StageKey` приложение строит ключ через:

```text
PBKDF2-HMAC-SHA1(StageKey, salt, 100000, dkLen=32)
```

а затем расшифровывает данные через:

```text
AES-256-CBC
```

На выходе получается скрытый DEX, который уже можно открыть в JADX.

## Hidden DEX: `lab.hiddenvm.RealVM`

Внутри decrypted payload настоящая логика сидит в:

```text
lab.hiddenvm.RealVM
```

Здесь проявляется важная идея дизайна:

- финальный ключ для расшифровки флага не строится из одного `StageKey`
- Java сначала вычисляет промежуточный 32-байтный share
- этот share отправляется в native `Night.bridge(...)`
- native-код уже достраивает настоящий финальный ключ

То есть логика намеренно разделена между:

- Java-side derivation
- native-side finalization

Поэтому "решить только один слой" не получится.

## Формула Java-side share

Скрытый DEX считает 32-байтный `javaShare` примерно так:

```text
SHA-256("NightNight.RealVM.v2" || stageKey || SHARE_CT || JAVA_NONCE)
```

После этого:

```text
bridgeKey = Night.bridge(javaShare)
```

а потом:

```text
flag = AES-256-CBC-decrypt(FLAG_CT, bridgeKey, zero_iv)
```

Значит, даже найдя `FLAG_CT`, `SHARE_CT`, `JAVA_NONCE` и порядок конкатенации, мы всё равно обязаны правильно разобрать `Night.bridge(...)`.

## Native bridge

После возврата в Ghidra финальная native-функция принимает 32-байтный Java share и прогоняет его через ещё один преобразователь.

Это последняя "дверь".

Логика bridge обычно дополнительно проверяет:

- длину share
- содержимое share после внутренних миксов
- poisoned anti-debug state

И только затем строит настоящий AES-ключ для итогового flag ciphertext.

Когда `bridgeKey` восстановлен правильно, финальная расшифровка начинает сходиться.

## Полный solve path

Итоговое решение выглядит так:

1. открыть APK в JADX
2. найти `Night.loadKey`, `Night.prepareVM`, `Night.bridge`
3. извлечь `libsilence.so`
4. восстановить runtime string decoder
5. проследить динамический `RegisterNatives`
6. снять или смоделировать anti-debug poisoning
7. реверснуть `pre_transform`
8. дешифровать и заэмулировать native VM
9. реверснуть `post_transform` и получить `StageKey`
10. расшифровать hidden DEX через PBKDF2 + AES-CBC
11. открыть `lab.hiddenvm.RealVM`
12. восстановить Java-side share derivation
13. реверснуть `Night.bridge(byte[])`
14. получить финальный `bridgeKey`
15. расшифровать flag ciphertext

## Почему таск хороший

Сильная сторона `nightnight.apk` в том, что по отдельности его элементы не выглядят экзотическими:

- JNI registration tricks
- anti-debug poisoning
- encrypted string tables
- hidden DEX loading
- маленькая кастомная VM
- PBKDF2 + AES wrapping

Но когда всё это связывается в одну цепочку, приходится идти очень дисциплинированно.
Почти любая попытка "срезать угол" дает правдоподобный, но неправильный промежуточный результат.

Это и есть главный замысел задачи:

- каждый слой выглядит почти достаточным
- но только полная цепочка приводит к настоящему флагу

## Примечание

В этом workspace у меня был сам APK и подробный локальный outline пайплайна реверса, но не было уже готовых эмуляторов и финально расшифрованных байтов флага.
Поэтому я оформил райтап вокруг реальной архитектуры решения и потока артефактов, а не стал выдумывать фальшивый финальный флаг.
