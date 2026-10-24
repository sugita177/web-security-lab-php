<?php
// PHPのsession_start()がデフォルトで勝手に出力してしまう「Pragma: no-cache」「Expires: 1981年」を停止
session_cache_limiter('');
session_start();

// 防御モードに応じたCache-Controlの切り替え
$cacheDefense = $_SESSION['defense_mode_cache'] ?? false;

header('Content-Type: image/svg+xml');

if ($cacheDefense) {
    // 防御ON: ディスク保存を禁止（毎回サーバー通信）
    header('Cache-Control: no-store, private');
    header('Pragma: no-cache');
    header('Expires: 0');
} else {
    // 防御OFF: ディスクキャッシュを1時間許可（disk cacheになる）
    header('Cache-Control: public, max-age=3600');
    header('Expires: ' . gmdate('D, d M Y H:i:s \G\M\T', time() + 3600));
}

// 山田太郎さんのアバター画像（SVG）を出力
echo <<<SVG
<svg xmlns="http://www.w3.org/2000/svg" width="60" height="60" viewBox="0 0 24 24" fill="#2563eb">
    <path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/>
</svg>
SVG;
exit;
