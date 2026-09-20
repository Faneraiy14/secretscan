<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;

abstract class FileFixtureTestCase extends TestCase
{
    /** @var list<string> */
    private array $tmpDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tmpDirs as $dir) {
            $this->rrmdir($dir);
        }
        $this->tmpDirs = [];
    }

    protected function tempFile(string $contents, string $name = 'test.txt'): string
    {
        $dir = sys_get_temp_dir() . '/secretscan_test_' . uniqid('', true);
        mkdir($dir);
        $this->tmpDirs[] = $dir;
        $path = $dir . '/' . $name;
        file_put_contents($path, $contents);
        return $path;
    }

    protected function tempDir(): string
    {
        $dir = sys_get_temp_dir() . '/secretscan_test_dir_' . uniqid('', true);
        mkdir($dir);
        $this->tmpDirs[] = $dir;
        return $dir;
    }

    private function rrmdir(string $dir): void
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
            is_dir($itemPath) ? $this->rrmdir($itemPath) : unlink($itemPath);
        }
        rmdir($dir);
    }
}
