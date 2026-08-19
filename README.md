# secretscan

CLI-утиліта, що шукає випадково закомічені секрети (API-ключі, токени,
приватні ключі) у файлах проєкту — до того, як вони потраплять у git
разом з рештою коду.

## Навіщо

Токен, вставлений прямо в код "тимчасово, потім винесу", лишається в
git-історії назавжди, навіть якщо його видалити наступним комітом.
`secretscan` ловить це до коміту (`--fix` тут не потрібен — секрет не
можна "автовиправити", тільки прибрати руками й перевипустити).

## Встановлення

```bash
git clone https://github.com/Faneraiy14/secretscan.git
cd secretscan
composer install --no-dev
```

Або без composer — залежностей нема, `php bin/secretscan` працює одразу
з клону.

## Використання

```bash
php bin/secretscan                      # поточна папка
php bin/secretscan src/                 # конкретна папка чи файл
php bin/secretscan --json               # машинозчитуваний вивід для CI
```

`.git/`, `node_modules/`, `vendor/` пропускаються завжди — там або
службові дані, або чужий код.

## Що ловить

| Правило | Приклад |
|---|---|
| GitHub Personal Access Token | `ghp_...`, `github_pat_...` |
| AWS Access Key ID | `AKIA...` |
| Slack Token | `xoxb-...`, `xoxp-...` |
| Stripe Live Key | `sk_live_...`, `pk_live_...` |
| Google API Key | `AIza...` |
| Anthropic API Key | `sk-ant-...` |
| OpenAI API Key | `sk-...`, `sk-proj-...` |
| Database Connection String | пароль прямо в URL: `postgres://user:pass@host`, `mysql://...`, `mongodb(+srv)://...`, `redis://...` |
| Приватний ключ | блок `-----BEGIN ... PRIVATE KEY-----` |
| Generic Bearer Token | `Bearer eyJ...` |
| Generic Secret Assignment | `password = "..."`, `api_key: "..."` |
| High Entropy String (Шеннон) | будь-який рядковий літерал ≥20 символів з ентропією ≥4.0 біт/символ — ловить власні токени без відомого формату |

Значення, що виглядають як заглушка (`your_key_here`, `changeme`,
`example`, `<...>`, `{{...}}` тощо), пропускаються — інакше кожен
`.env.example` провалював би перевірку.

Ентропійна перевірка — евристика, а не точний детектор: реальний текст
(речення, ідентифікатори) має помітно нижчу ентропію на символ, ніж
випадковий base64/hex, тож хибні спрацювання рідкісні, але можливі —
позначай такі `secretscan:ignore`.

## Redaction

Знайдене значення в консолі й у `--json` завжди показується частково:
перші й останні 4 символи, решта — зірочки. Досить, щоб впізнати "той
самий" секрет, замало, щоб хтось підглянув його зі скріншота логів CI.

## Хибні спрацювання

Якщо якийсь рядок навмисно містить приклад/фікстуру, що виглядає як
секрет (тести, документація) — додай коментар `secretscan:ignore` в
кінці рядка, і його пропустять:

```php
$fakeToken = "ghp_exampleexampleexampleexampleexam1"; // secretscan:ignore
```

## У CI

Готовий GitHub Action — підключи в будь-якому репозиторії без composer
install, PHP ставиться автоматично:

```yaml
- uses: actions/checkout@v4
- uses: Faneraiy14/secretscan@main
  with:
    path: .   # необов'язково, за замовчуванням '.'
```

Крок падає (exit 1), якщо знайдено підозрілі значення — це блокує merge
через required status check у налаштуваннях гілки GitHub.

Або вручну, без composite action:

```yaml
- run: php bin/secretscan --json || exit 1
```

Exit-код 1, якщо щось знайдено, 0 — якщо чисто, 2 — помилка (напр.
неіснуючий шлях).

## Тести

```bash
php tests/run.php
```

28 перевірок: кожне правило окремо (включно з ентропійною), редагування
значення, заглушки, бінарні файли, рекурсія й виключення папок,
`secretscan:ignore`, дедуплікація regex/ентропія на тому самому
значенні, CLI-рівень (`--json`, exit-коди, `--help`) через реальний
виклик процесу.

## Ліцензія

MIT — див. [LICENSE](LICENSE). Автор — Faneraiy14.
