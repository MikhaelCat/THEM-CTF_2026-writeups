# A Cute Magical Router Gateway writeup

## Задание

Дан веб-таск `A Cute Magical Router Gateway` с описанием:

```text
A Router was found in the backrooms at THEM hq.

Looks really old, "stone paper scissors" etched on the back, whatever that means. I plugged the router into power, visited the default gateway with no room for caution whatsoever. Since this was found at THEM hq, I feel like the password might contain the string "them", but I have no clue honestly.

Pls help find the password :3
```

Формат флага:

```text
THEM?!CTF{...}
```

## Первый взгляд

По исходникам из репозитория backend - это маленький Flask-сервис с маршрутами:

- `/`
- `/validate-password`
- `/flag`

На первый взгляд intended идея очень похожа на сиквел:

- на сервере лежат зашифрованные username и password
- проверка логина течет по времени
- условие намекает, что пароль, возможно, содержит `them`

И действительно, тайминговая утечка в валидаторе есть.

## Логика валидатора

Интересный маршрут выглядит так:

```python
@app.route('/validate-password', methods=['POST'])
def validate_password():
    ...
    if(len(username) != 45):
        return fail
    time.sleep(1)

    if username != decrypt_data(ENCRYPTED_USERNAME, private_key):
        return fail
    time.sleep(1)

    if (len(password) != 19):
        return fail
    time.sleep(1)

    if password == decrypt_data(ENCRYPTED_PASSWORD, private_key):
        return success
```

То есть endpoint выдает прогресс проверки через время ответа:

- неверная длина username: почти мгновенный fail
- правильная длина username, но неверный username: около 1 секунды
- правильный username, но неверная длина password: около 2 секунд
- правильный username и длина password, но неверный password: около 3 секунд

Из этого видно, что **intended** путь решения был примерно таким:

1. определить длину username
2. восстановить правильный username
3. определить длину password
4. перебрать правдоподобные кандидаты пароля через timing oracle

Это полностью совпадает с идеей таска.

## Но реальное решение оказалось гораздо проще

В README самого репозитория автор прямо пишет, что в задаче осталась unintended уязвимость.

И backend это подтверждает:

```python
@app.route('/flag')
def get_flag():
    return jsonify({"flag": os.environ.get('FLAG', 'THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}')})
```

То есть вместо восстановления логина и пароля через тайминг можно просто сделать запрос:

```text
GET /flag
```

и сервер сразу вернет флаг в JSON.

Никакая аутентификация не нужна.

## Эксплуатация

Эксплойт состоит буквально из одного запроса:

```http
GET /flag HTTP/1.1
Host: <target>
```

Ответ:

```json
{"flag":"THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}"}
```

## Почему так произошло

Похоже, сервис изначально задумывался как тайминг-челлендж на login flow, но в коде случайно оставили helper/debug endpoint:

- `/validate-password` содержит настоящую intended логику
- `/flag` полностью обходит ее и сразу отдает секрет

Из-за этого опубликованная задача стала заметно проще, чем планировалось.

## Intended vs actual solve

### Intended

- использовать timing oracle на `/validate-password`
- опираться на length checks и `time.sleep`
- восстановить корректные креды

### Actual

- полностью игнорировать login flow
- сходить на `/flag`
- прочитать флаг из JSON

## Итоговый флаг

```text
THEM?!CTF{5l0w_4nd_5734dy_l34k5_7h3_fl4g}
```
