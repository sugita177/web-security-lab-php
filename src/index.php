<?php
declare(strict_types=1);

// Web Security Lab 初期エントリーポイント
header('Content-Type: text/plain; charset=utf-8');

echo "===============================================\n";
echo " Web Security Lab (PHP " . PHP_VERSION . ")\n";
echo " Server Software: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') . "\n";
echo " Remote Address:  " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown') . "\n";
echo "===============================================\n";
echo "Status: OK. Ready for Phase 1!\n";
