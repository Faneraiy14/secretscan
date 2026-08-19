<?php

declare(strict_types=1);

namespace SecretScan;

final class SecretScanner
{
    /** @var array<string,string> назва правила => regex */
    private array $rules;

    /** @var string[] значення, які виглядають як секрет за формою, але
     *  насправді заглушка — інакше .env.example із "API_KEY=your_key_here"
     *  постійно провалював би перевірку. */
    private const PLACEHOLDER_MARKERS = [
        'xxx', 'changeme', 'change_me', 'example', 'sample', 'placeholder',
        'your_', 'your-', 'replace', 'todo', 'fixme', 'dummy', 'fake',
        '<', '{{', '${', 'test_key', 'testkey',
    ];

    // Регексами ловимо тільки ВІДОМІ форми секретів (ghp_, AKIA, ...).
    // Ентропійна перевірка (Шеннон) — доповнення для випадкових на
    // вигляд рядків, що не збігаються з жодним відомим форматом: власні
    // токени, внутрішні API-ключі тощо. Довжина й поріг підібрані так,
    // щоб не спрацьовувати на звичайних словах/реченнях (природна мова
    // має помітно нижчу ентропію на символ, ніж випадковий base64/hex).
    private const ENTROPY_MIN_LENGTH = 20;
    private const ENTROPY_THRESHOLD = 4.0;

    /**
     * @param array<string,string>|null $extraRules додаткові правила
     *        (назва => regex), об'єднуються з дефолтними, можуть їх
     *        перекривати за назвою.
     */
    public function __construct(?array $extraRules = null)
    {
        $this->rules = self::defaultRules();
        if ($extraRules !== null) {
            $this->rules = array_merge($this->rules, $extraRules);
        }
    }

    /**
     * @return array<string,string>
     */
    public static function defaultRules(): array
    {
        return [
            'GitHub Personal Access Token' => '/\bgh[pousr]_[A-Za-z0-9]{36,}\b/',
            'GitHub Fine-Grained PAT' => '/\bgithub_pat_[A-Za-z0-9_]{20,}\b/',
            'AWS Access Key ID' => '/\bAKIA[0-9A-Z]{16}\b/',
            'Slack Token' => '/\bxox[baprs]-[A-Za-z0-9-]{10,}\b/',
            'Stripe Live Key' => '/\b(sk|pk|rk)_live_[A-Za-z0-9]{16,}\b/',
            'Google API Key' => '/\bAIza[0-9A-Za-z\-_]{35}\b/',
            // (?!ant-) — щоб не дублювати "OpenAI API Key" нижче на кожному
            // Anthropic-ключі: обидва починаються на "sk-", далі формати
            // структурно різні (в Anthropic після "ant-" завжди дефіс, тому
            // в OpenAI-патерні природно й так не збіглося б — виняток тут
            // явний, а не випадковий побічний ефект).
            'Anthropic API Key' => '/\bsk-ant-[A-Za-z0-9\-_]{20,}\b/',
            'OpenAI API Key' => '/\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9\-_]{20,}\b/',
            // scheme://user:pass@host — інша поверхня, ніж Generic Secret
            // Assignment нижче (та шукає "ключ = значення", ця — пароль,
            // вбудований прямо в URL підключення до БД/кешу).
            'Database Connection String' => '/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\/\s"\']+:[^@\/\s"\']+@/',
            'Private Key Block' => '/-----BEGIN[ A-Z]*PRIVATE KEY-----/',
            'Generic Bearer Token' => '/\bBearer\s+[A-Za-z0-9\-._~+\/]{20,}=*/',
            // [:=]>? замість просто [:=] — інакше PHP-масиви ("password" => "...")
            // не матчились би: після ключа й закриваючої лапки йде саме "=>".
            'Generic Secret Assignment' => '/\b(secret|password|passwd|api[_-]?key|access[_-]?key|auth[_-]?token)["\']?\s*[:=]>?\s*["\']([A-Za-z0-9\-_\/+=.]{16,})["\']/i',
        ];
    }

    /**
     * @param string[] $excludeDirs назви папок, які повністю пропускаються
     *        (за замовчуванням .git/node_modules/vendor — там або службові
     *        дані, або чужий код, який не наша справа перевіряти)
     * @return Finding[]
     */
    public function scan(string $path, array $excludeDirs = ['.git', 'node_modules', 'vendor']): array
    {
        if (!file_exists($path)) {
            throw new \RuntimeException("Шлях не існує: {$path}");
        }

        $findings = [];
        foreach ($this->collectFiles($path, $excludeDirs) as $file) {
            foreach ($this->scanFile($file) as $finding) {
                $findings[] = $finding;
            }
        }

        return $findings;
    }

    /**
     * @return Finding[]
     */
    public function scanFile(string $file): array
    {
        if ($this->looksBinary($file)) {
            return [];
        }

        $contents = file_get_contents($file);
        if ($contents === false) {
            return [];
        }

        $findings = [];
        $lines = explode("\n", $contents);
        foreach ($lines as $lineIndex => $line) {
            // Явна позначка "це навмисно, не справжній секрет" — потрібна
            // тестам самого secretscan (фікстури з фейковими токенами) і
            // будь-кому іншому, хто свідомо лишає приклад у коді/доках.
            if (str_contains($line, 'secretscan:ignore')) {
                continue;
            }
            $foundOnLine = [];
            foreach ($this->rules as $ruleName => $pattern) {
                if (!preg_match_all($pattern, $line, $matches, PREG_SET_ORDER)) {
                    continue;
                }
                foreach ($matches as $match) {
                    // Правила з capture-групою секрету (Generic Secret
                    // Assignment) редагують саме групу 2, не весь рядок
                    // "password=..." цілком — інакше в редагованому виводі
                    // лишалось би ім'я поля, а не значення.
                    $secretValue = $match[2] ?? $match[0];
                    if ($this->looksLikePlaceholder($secretValue)) {
                        continue;
                    }
                    $foundOnLine[$secretValue] = true;
                    $findings[] = new Finding(
                        file: $file,
                        line: $lineIndex + 1,
                        rule: $ruleName,
                        redacted: $this->redact($secretValue)
                    );
                }
            }

            foreach ($this->scanEntropyCandidates($line) as $candidate) {
                // Уже знайдено конкретним regex-правилом на цьому рядку —
                // не дублювати тим самим значенням під іншою назвою.
                if (isset($foundOnLine[$candidate]) || $this->looksLikePlaceholder($candidate)) {
                    continue;
                }
                $findings[] = new Finding(
                    file: $file,
                    line: $lineIndex + 1,
                    rule: 'High Entropy String (Shannon)',
                    redacted: $this->redact($candidate)
                );
            }
        }

        return $findings;
    }

    /**
     * Кандидати на "випадковий на вигляд" секрет: рядкові літерали в
     * лапках достатньої довжини з ентропією Шеннона вище порогу. Не
     * прив'язано до конкретного імені змінної/ключового слова — на
     * відміну від Generic Secret Assignment, тут ловимо власні токени,
     * яких жодне з відомих правил не очікує.
     *
     * @return string[]
     */
    private function scanEntropyCandidates(string $line): array
    {
        $pattern = '/["\']([A-Za-z0-9+\/_=\-]{' . self::ENTROPY_MIN_LENGTH . ',})["\']/';
        if (!preg_match_all($pattern, $line, $matches)) {
            return [];
        }

        $candidates = [];
        foreach ($matches[1] as $candidate) {
            if ($this->shannonEntropy($candidate) >= self::ENTROPY_THRESHOLD) {
                $candidates[] = $candidate;
            }
        }
        return $candidates;
    }

    // Ентропія Шеннона в бітах на символ: -Σ p(c)·log2(p(c)) за частотами
    // символів у рядку. Випадковий base64/hex-рядок близький до
    // максимуму для свого алфавіту; звичайний текст/ідентифікатор —
    // помітно нижче через нерівномірний розподіл символів.
    private function shannonEntropy(string $value): float
    {
        $len = strlen($value);
        if ($len === 0) {
            return 0.0;
        }

        $frequency = [];
        for ($i = 0; $i < $len; $i++) {
            $char = $value[$i];
            $frequency[$char] = ($frequency[$char] ?? 0) + 1;
        }

        $entropy = 0.0;
        foreach ($frequency as $count) {
            $probability = $count / $len;
            $entropy -= $probability * log($probability, 2);
        }
        return $entropy;
    }

    /**
     * @param string[] $excludeDirs
     * @return \Generator<string>
     */
    private function collectFiles(string $path, array $excludeDirs): \Generator
    {
        if (is_file($path)) {
            yield $path;
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($path, \FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $fileInfo) {
            /** @var \SplFileInfo $fileInfo */
            foreach ($excludeDirs as $dir) {
                if (str_contains($fileInfo->getPathname(), DIRECTORY_SEPARATOR . $dir . DIRECTORY_SEPARATOR)) {
                    continue 2;
                }
            }
            if ($fileInfo->isFile()) {
                yield $fileInfo->getPathname();
            }
        }
    }

    // Перевіряє перші 512 байт на нуль-байт — надійна й дешева евристика
    // "це не текстовий файл" без залежності від file_info/mime.
    private function looksBinary(string $file): bool
    {
        $handle = @fopen($file, 'rb');
        if ($handle === false) {
            return true;
        }
        $chunk = fread($handle, 512);
        fclose($handle);
        return $chunk !== false && str_contains($chunk, "\0");
    }

    private function looksLikePlaceholder(string $value): bool
    {
        $lower = strtolower($value);
        foreach (self::PLACEHOLDER_MARKERS as $marker) {
            if (str_contains($lower, $marker)) {
                return true;
            }
        }
        return false;
    }

    // Лишає перші 4 і останні 4 символи, решту ховає — досить, щоб
    // впізнати "той самий" секрет у виводі, замало, щоб хтось підглянув
    // його зі скріншота чи логу CI.
    private function redact(string $value): string
    {
        $len = strlen($value);
        if ($len <= 10) {
            return str_repeat('*', $len);
        }
        return substr($value, 0, 4) . str_repeat('*', $len - 8) . substr($value, -4);
    }
}
