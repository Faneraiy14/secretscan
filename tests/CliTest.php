<?php

declare(strict_types=1);

namespace Tests;

final class CliTest extends FileFixtureTestCase
{
    /**
     * @param list<string> $args
     * @return array{0: int, 1: string}
     */
    private function runCli(array $args): array
    {
        $command = array_merge([PHP_BINARY, __DIR__ . '/../bin/secretscan'], $args);
        $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
        $this->assertIsResource($process);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $exitCode = proc_close($process);
        return [$exitCode, trim((string) $stdout)];
    }

    public function testACleanDirectoryReportsOkAndExitsZero(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/ok.txt', 'нема тут нічого цікавого');

        [$exitCode, $stdout] = $this->runCli([$dir, '--json']);
        $decoded = json_decode($stdout, true);

        $this->assertIsArray($decoded);
        $this->assertTrue($decoded['ok']);
        $this->assertSame(0, $exitCode);
    }

    public function testADirtyDirectoryReportsFindingsAndExitsOne(): void
    {
        $dir = $this->tempDir();
        file_put_contents($dir . '/leak.txt', 'ghp_' . str_repeat('e', 36));

        [$exitCode, $stdout] = $this->runCli([$dir, '--json']);
        $decoded = json_decode($stdout, true);

        $this->assertIsArray($decoded);
        $this->assertFalse($decoded['ok']);
        $this->assertSame(1, $exitCode);
        $this->assertCount(1, $decoded['findings']);
    }

    public function testHelpFlagExitsZeroAndPrintsUsage(): void
    {
        [$exitCode, $stdout] = $this->runCli(['--help']);
        $this->assertSame(0, $exitCode);
        $this->assertStringContainsString('secretscan', $stdout);
    }
}
