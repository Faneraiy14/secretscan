<?php

declare(strict_types=1);

namespace Tests;

use SecretScan\SecretScanner;

final class ScanBehaviorTest extends FileFixtureTestCase
{
    private SecretScanner $scanner;

    protected function setUp(): void
    {
        $this->scanner = new SecretScanner();
    }

    public function testBinaryFilesAreSkippedNotScannedAsText(): void
    {
        $f = $this->tempFile("PNG\x00\x01\x02" . 'ghp_' . str_repeat('a', 36), 'fake.bin');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testRecursiveScanExcludesGitVendorAndNodeModules(): void
    {
        $dir = $this->tempDir();
        mkdir($dir . '/src');
        mkdir($dir . '/.git');
        mkdir($dir . '/vendor');
        file_put_contents($dir . '/src/config.php', '$token = "ghp_' . str_repeat('b', 36) . '";');
        file_put_contents($dir . '/.git/config', 'ghp_' . str_repeat('c', 36));
        file_put_contents($dir . '/vendor/lib.php', 'ghp_' . str_repeat('d', 36));

        $findings = $this->scanner->scan($dir);

        $this->assertCount(1, $findings);
        $this->assertStringContainsString('config.php', $findings[0]->file);
    }

    public function testSecretscanIgnoreCommentSuppressesTheFindingOnThatLine(): void
    {
        $f = $this->tempFile('const TOKEN = "ghp_' . str_repeat('a', 36) . '" // secretscan:ignore');
        $findings = $this->scanner->scanFile($f);
        $this->assertSame([], $findings);
    }

    public function testScanningANonexistentPathThrows(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->scanner->scan('/шлях/якого/не/існує');
    }
}
