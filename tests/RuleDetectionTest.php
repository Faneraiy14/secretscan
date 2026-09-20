<?php

declare(strict_types=1);

namespace Tests;

use SecretScan\SecretScanner;

final class RuleDetectionTest extends FileFixtureTestCase
{
    private SecretScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new SecretScanner();
    }

    public function testGitHubPersonalAccessToken(): void
    {
        $f = $this->tempFile('const TOKEN = "ghp_' . str_repeat('a', 36) . '"');
        $findings = $this->scanner->scanFile($f);
        $this->assertCount(1, $findings);
        $this->assertSame('GitHub Personal Access Token', $findings[0]->rule);
    }

    public function testAwsAccessKeyIdWithoutAPlaceholderWordIsFound(): void
    {
        $f = $this->tempFile('AWS_KEY=AKIAZZZZZZZZZZZZZZZZ'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertGreaterThanOrEqual(1, count($findings));
    }

    public function testTheOfficialAwsExampleKeyIsFilteredAsAPlaceholder(): void
    {
        // AKIAIOSFODNN7EXAMPLE - офіційний приклад-заглушка AWS, "EXAMPLE"
        // у значенні має спрацювати як плейсхолдер-слово.
        $f = $this->tempFile('AWS_KEY=AKIAIOSFODNN7EXAMPLE');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testPrivateKeyBlock(): void
    {
        $f = $this->tempFile("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('Private Key Block', $findings[0]->rule);
    }

    public function testGenericSecretAssignmentIsFoundAndRedacted(): void
    {
        $f = $this->tempFile('$config = ["password" => "SuperSecretValue123456"];'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('Generic Secret Assignment', $findings[0]->rule);
        $this->assertStringNotContainsString('SuperSecretValue123456', $findings[0]->redacted); // secretscan:ignore
    }

    public function testEnvExampleStylePlaceholdersAreNotFlagged(): void
    {
        $f = $this->tempFile('API_KEY=your_api_key_here' . "\n" . 'PASSWORD="changeme_please"');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testValueIsRedactedKeepingOnlyFirstAndLastFourCharacters(): void
    {
        $f = $this->tempFile('const TOKEN = "ghp_ABCD1234567890123456789012345678EFGH"'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);

        $redacted = $findings[0]->redacted;
        $this->assertStringStartsWith('ghp_', $redacted);
        $this->assertStringContainsString('***', $redacted);
        $this->assertSame(strlen('ghp_ABCD1234567890123456789012345678EFGH'), strlen($redacted)); // secretscan:ignore
    }

    public function testHighEntropyStringCatchesAnUnknownFormatToken(): void
    {
        $f = $this->tempFile('const INTERNAL_TOKEN = "aB3xK9mQ7pL2vN8wZ1tR6yU4sD0fG5hJ"'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('High Entropy String (Shannon)', $findings[0]->rule);
    }

    public function testAnOrdinaryEnglishSentenceIsNotHighEntropy(): void
    {
        $f = $this->tempFile('const MESSAGE = "this is just a normal english sentence value"');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testARegexRuleMatchIsNotDuplicatedByTheEntropyRule(): void
    {
        $f = $this->tempFile('const TOKEN = "ghp_' . str_repeat('a', 36) . '"');
        $findings = $this->scanner->scanFile($f);
        $this->assertCount(1, $findings);
    }

    public function testAnthropicApiKey(): void
    {
        $f = $this->tempFile('ANTHROPIC_API_KEY=sk-ant-api03-' . str_repeat('a', 40)); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertCount(1, $findings);
        $this->assertSame('Anthropic API Key', $findings[0]->rule);
    }

    public function testOpenAiApiKeyClassicFormat(): void
    {
        $f = $this->tempFile('OPENAI_API_KEY=sk-' . str_repeat('a', 48));
        $findings = $this->scanner->scanFile($f);
        $this->assertCount(1, $findings);
        $this->assertSame('OpenAI API Key', $findings[0]->rule);
    }

    public function testOpenAiApiKeyProjFormat(): void
    {
        $f = $this->tempFile('OPENAI_API_KEY=sk-proj-' . str_repeat('b', 40)); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('OpenAI API Key', $findings[0]->rule);
    }

    public function testAnthropicKeyIsNotDuplicatedByTheOpenAiRule(): void
    {
        $f = $this->tempFile('ANTHROPIC_API_KEY=sk-ant-api03-' . str_repeat('c', 40)); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $openAiMatches = array_filter($findings, static fn ($x) => $x->rule === 'OpenAI API Key');
        $this->assertCount(0, $openAiMatches);
    }

    public function testDatabaseConnectionStringPostgres(): void
    {
        $f = $this->tempFile('DATABASE_URL=postgres://myuser:MyS3cretPass123@db.example.com:5432/mydb'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('Database Connection String', $findings[0]->rule);
    }

    public function testDatabaseConnectionStringMongoSrv(): void
    {
        $f = $this->tempFile('MONGO_URI=mongodb+srv://admin:hunter2pass456@cluster0.example.net/test'); // secretscan:ignore
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('Database Connection String', $findings[0]->rule);
    }

    public function testUrlWithoutCredentialsIsNotAConnectionStringFinding(): void
    {
        $f = $this->tempFile('# просто приклад формату без облікових даних' . "\n" . 'REDIS_URL=redis://localhost:6379');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testAUuidIsNotFlaggedDespiteHighShannonEntropy(): void
    {
        $f = $this->tempFile('$sessionId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testASecondUuidIsAlsoIgnored(): void
    {
        $f = $this->tempFile('$recordId = "550e8400-e29b-41d4-a716-446655440000";');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testTheUuidExceptionIsNotTooWideARealTokenIsStillCaught(): void
    {
        $f = $this->tempFile('$token = "ghp_' . str_repeat('a', 36) . '";');
        $findings = $this->scanner->scanFile($f);
        $this->assertNotSame([], $findings);
        $this->assertSame('GitHub Personal Access Token', $findings[0]->rule);
    }
}
