<?php

declare(strict_types=1);

require __DIR__ . '/../src/Finding.php';
require __DIR__ . '/../src/SecretScanner.php';

use SecretScan\SecretScanner;

$failures = 0;
$passed = 0;

function check(string $label, bool $condition): void
{
    global $failures, $passed;
    if ($condition) {
        echo "  ✅ {$label}\n";
        $passed++;
    } else {
        echo "  ❌ {$label}\n";
        $failures++;
    }
}

function tempFile(string $contents, string $name = 'test.txt'): string
{
    $dir = sys_get_temp_dir() . '/secretscan_test_' . uniqid('', true);
    mkdir($dir);
    $path = $dir . '/' . $name;
    file_put_contents($path, $contents);
    return $path;
}

function rrmdir(string $dir): void
{
    if (!is_dir($dir)) {
        if (is_file($dir)) {
            unlink($dir);
        }
        return;
    }
    foreach (scandir($dir) ?: [] as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $itemPath = $dir . '/' . $item;
        is_dir($itemPath) ? rrmdir($itemPath) : unlink($itemPath);
    }
    rmdir($dir);
}

$scanner = new SecretScanner();

// --- Тест 1: GitHub PAT ---
echo "1. GitHub Personal Access Token\n";
$f = tempFile('const TOKEN = "ghp_' . str_repeat('a', 36) . '"');
$findings = $scanner->scanFile($f);
check('знайдено 1', count($findings) === 1);
check('правило "GitHub Personal Access Token"', $findings !== [] && $findings[0]->rule === 'GitHub Personal Access Token');
rrmdir(dirname($f));

// --- Тест 2: AWS Access Key ---
echo "2. AWS Access Key ID\n";
$f = tempFile('AWS_KEY=AKIAIOSFODNN7EXAMPLE');
$findings = $scanner->scanFile($f);
// AKIAIOSFODNN7EXAMPLE сам по собі офіційний приклад-заглушка AWS — але
// тут перевіряємо саме форму патерну, EXAMPLE у значенні спрацює як
// плейсхолдер і buде відфільтрований — навмисно беремо реалістичний
// формат без слова example, щоб перевірити сам regex.
$f2 = tempFile('AWS_KEY=AKIAZZZZZZZZZZZZZZZZ'); // secretscan:ignore
$findings2 = $scanner->scanFile($f2);
check('AKIA-ключ без плейсхолдер-слова знайдено', count($findings2) >= 1);
check('AKIAIOSFODNN7EXAMPLE (офіційний приклад AWS) відфільтровано як заглушка', $findings === []);
rrmdir(dirname($f));
rrmdir(dirname($f2));

// --- Тест 3: приватний ключ ---
echo "3. Private Key Block\n";
$f = tempFile("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"); // secretscan:ignore
$findings = $scanner->scanFile($f);
check('знайдено приватний ключ', $findings !== [] && $findings[0]->rule === 'Private Key Block');
rrmdir(dirname($f));

// --- Тест 4: generic secret assignment ---
echo "4. Generic Secret Assignment (password=\"...\")\n";
$f = tempFile('$config = ["password" => "SuperSecretValue123456"];'); // secretscan:ignore
$findings = $scanner->scanFile($f);
check('знайдено пароль', $findings !== [] && $findings[0]->rule === 'Generic Secret Assignment');
check('редаговано (не показує повне значення)', $findings !== [] && !str_contains($findings[0]->redacted, 'SuperSecretValue123456'));
rrmdir(dirname($f));

// --- Тест 5: плейсхолдери НЕ вважаються секретами ---
echo "5. Заглушки (.env.example-стиль) не провалюють сканування\n";
$f = tempFile('API_KEY=your_api_key_here' . "\n" . 'PASSWORD="changeme_please"');
$findings = $scanner->scanFile($f);
check('заглушки проігноровано', $findings === []);
rrmdir(dirname($f));

// --- Тест 6: бінарний файл пропускається ---
echo "6. Бінарні файли пропускаються (не падають з помилкою)\n";
$f = tempFile("PNG\x00\x01\x02" . 'ghp_' . str_repeat('a', 36), 'fake.bin');
$findings = $scanner->scanFile($f);
check('бінарний файл дав 0 знахідок (не скановано як текст)', $findings === []);
rrmdir(dirname($f));

// --- Тест 7: редагування значення ---
echo "7. Редагування значення (перші/останні 4 символи)\n";
$f = tempFile('const TOKEN = "ghp_ABCD1234567890123456789012345678EFGH"'); // secretscan:ignore
$findings = $scanner->scanFile($f);
check('знайдено', $findings !== []);
if ($findings !== []) {
    $redacted = $findings[0]->redacted;
    check('починається на ghp_', str_starts_with($redacted, 'ghp_'));
    check('містить зірочки в середині', str_contains($redacted, '***'));
    check('не містить повний токен', strlen($redacted) === strlen('ghp_ABCD1234567890123456789012345678EFGH')); // secretscan:ignore
}
rrmdir(dirname($f));

// --- Тест 8: рекурсивне сканування папки + виключення .git/vendor ---
echo "8. Рекурсивне сканування директорії, виключення .git/vendor/node_modules\n";
$dir = sys_get_temp_dir() . '/secretscan_test_dir_' . uniqid('', true);
mkdir($dir);
mkdir($dir . '/src');
mkdir($dir . '/.git');
mkdir($dir . '/vendor');
file_put_contents($dir . '/src/config.php', '$token = "ghp_' . str_repeat('b', 36) . '";');
file_put_contents($dir . '/.git/config', 'ghp_' . str_repeat('c', 36));
file_put_contents($dir . '/vendor/lib.php', 'ghp_' . str_repeat('d', 36));
$findings = $scanner->scan($dir);
check('знайдено лише в src/ (1 знахідка)', count($findings) === 1);
check('файл саме src/config.php', $findings !== [] && str_contains($findings[0]->file, 'config.php'));
rrmdir($dir);

// --- Тест 8б: secretscan:ignore пригнічує знахідку на цьому рядку ---
echo "8б. Мітка secretscan:ignore пригнічує спрацювання на рядку\n";
$f = tempFile('const TOKEN = "ghp_' . str_repeat('a', 36) . '" // secretscan:ignore');
$findings = $scanner->scanFile($f);
check('рядок з міткою не дав знахідок', $findings === []);
rrmdir(dirname($f));

// --- Тест 9: неіснуючий шлях кидає виняток ---
echo "9. Неіснуючий шлях — RuntimeException\n";
$threw = false;
try {
    $scanner->scan('/шлях/якого/не/існує');
} catch (\RuntimeException) {
    $threw = true;
}
check('кинуто RuntimeException', $threw);

// --- Тест 10: CLI як окремий процес ---
echo "10. CLI: --json, exit-коди через реальний процес\n";

function runCli(array $args): array
{
    $command = array_merge([PHP_BINARY, __DIR__ . '/../bin/secretscan'], $args);
    $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    $stdout = stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    return [$exitCode, trim((string) $stdout)];
}

$dirClean = sys_get_temp_dir() . '/secretscan_cli_clean_' . uniqid('', true);
mkdir($dirClean);
file_put_contents($dirClean . '/ok.txt', 'нема тут нічого цікавого');
[$exitClean, $outClean] = runCli([$dirClean, '--json']);
$decodedClean = json_decode($outClean, true);
check('чиста папка: ok=true', $decodedClean !== null && $decodedClean['ok'] === true);
check('чиста папка: exit=0', $exitClean === 0);
rrmdir($dirClean);

$dirDirty = sys_get_temp_dir() . '/secretscan_cli_dirty_' . uniqid('', true);
mkdir($dirDirty);
file_put_contents($dirDirty . '/leak.txt', 'ghp_' . str_repeat('e', 36));
[$exitDirty, $outDirty] = runCli([$dirDirty, '--json']);
$decodedDirty = json_decode($outDirty, true);
check('брудна папка: ok=false', $decodedDirty !== null && $decodedDirty['ok'] === false);
check('брудна папка: exit=1', $exitDirty === 1);
check('брудна папка: findings містить 1 елемент', $decodedDirty !== null && count($decodedDirty['findings']) === 1);
rrmdir($dirDirty);

[$exitHelp, $outHelp] = runCli(['--help']);
check('--help: exit=0', $exitHelp === 0);
check('--help: показує "secretscan"', str_contains($outHelp, 'secretscan'));

echo "\n======================================\n";
echo "Успішно: {$passed} | Провалено: {$failures}\n";

if ($failures > 0) {
    echo "Є провалені тести.\n";
    exit(1);
}

echo "Усі тести пройдено.\n";
exit(0);
