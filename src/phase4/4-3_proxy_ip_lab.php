<?php
session_start();

// 許可された社内ネットワークのIPアドレス
const ALLOWED_INTERNAL_IP = '192.168.100.50';

// 信頼できるプロキシサーバー（Nginx / ロードバランサー）のIPまたはCIDR
// Docker環境では通常 172.16.0.0/12 や 127.0.0.1 が内部ネットワーク
const TRUSTED_PROXIES = ['127.0.0.1', '::1'];

// モード管理（デフォルト: vulnerable）
$mode = $_GET['mode'] ?? 'vulnerable';
if (!in_array($mode, ['vulnerable', 'secure'], true)) {
    $mode = 'vulnerable';
}

/**
 * 脆弱なクライアントIP取得ロジック
 * 攻撃者が送信した X-Forwarded-For を無批判に信用してしまう
 */
function getClientIpVulnerable(): string {
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // カンマ区切りの最初のIP、またはヘッダーそのままを取得してしまう典型的なミス
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim($ips[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

/**
 * 【TODO 1: 安全なクライアントIP解決ロジックを実装してください】
 *
 * 【要件】
 * 1. 直前のTCP接続元（$_SERVER['REMOTE_ADDR']）が、信頼できるプロキシ（TRUSTED_PROXIES または Docker内部IP）
 *    からの通信である場合のみ、プロキシヘッダー（X-Forwarded-For）を参照する。
 *    ※信頼できない外部から直接届いたリクエストの場合は、ヘッダーを無視して REMOTE_ADDR をそのまま返す。
 *
 * 2. X-Forwarded-For ヘッダーに複数のIPがカンマ区切りで含まれている場合:
 *    「末尾（右側）」が直前のプロキシによって追記された最も信頼できるIP情報である。
 *    先頭（左端）はクライアント（攻撃者）が任意に捏造できるため、安易に先頭を採用してはならない。
 *
 * ヒント:
 * - 直前の接続元（$_SERVER['REMOTE_ADDR']）が信頼できるかチェック
 * - 信頼できない接続元なら、ヘッダーは見ずに $_SERVER['REMOTE_ADDR'] を返す
 * - 信頼できる接続元なら、X-Forwarded-For をカンマ区切りで分解し、安全なIPを取り出す
 */
function getClientIpSecure(): string {
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

    // =========================================================================
    // ここに安全なクライアントIP判定ロジックを実装してください
    // =========================================================================
    $isFromCorrectProxy = in_array($remoteAddr, TRUSTED_PROXIES, true);
    if ($isFromCorrectProxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        // カンマ区切りの最後のIPを取得する
        $ips = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        return trim(end($ips));
    }
    return $remoteAddr;
}

// Web画面からのシミュレーション用パラメータ処理
$simulatedXff = $_POST['simulated_xff'] ?? $_GET['simulated_xff'] ?? null;
$simulatedRemote = $_POST['simulated_remote'] ?? $_GET['simulated_remote'] ?? null;

// シミュレーション値があれば $_SERVER に反映（未指定時は実環境の値）
$originalRemoteAddr = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
$originalXff = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';

if ($simulatedXff !== null) {
    if ($simulatedXff === '') {
        unset($_SERVER['HTTP_X_FORWARDED_FOR']);
    } else {
        $_SERVER['HTTP_X_FORWARDED_FOR'] = $simulatedXff;
    }
}
if ($simulatedRemote !== null && $simulatedRemote !== '') {
    $_SERVER['REMOTE_ADDR'] = $simulatedRemote;
}

// 現在のモードに応じたクライアントIPの解決
$detectedIp = ($mode === 'secure') ? getClientIpSecure() : getClientIpVulnerable();

// 社内IP判定
$isAllowed = ($detectedIp === ALLOWED_INTERNAL_IP);

?>
<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>Phase 4-3: プロキシヘッダーと信頼性境界（IP偽装）</title>
    <style>
        body { font-family: sans-serif; max-width: 850px; margin: 30px auto; padding: 0 15px; background: #f8fafc; color: #1e293b; }
        .card { background: white; border-radius: 8px; padding: 25px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; }
        .badge-vulnerable { background: #fee2e2; color: #991b1b; }
        .badge-secure { background: #dcfce7; color: #166534; }
        .alert { padding: 15px; border-radius: 6px; margin-bottom: 15px; }
        .alert-success { background: #dcfce7; border-left: 5px solid #16a34a; color: #166534; }
        .alert-danger { background: #fee2e2; border-left: 5px solid #dc2626; color: #991b1b; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }
        th { background: #f1f5f9; width: 35%; }
        pre { background: #1e293b; color: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; font-size: 0.9em; }
        .btn { display: inline-block; padding: 8px 16px; border-radius: 4px; text-decoration: none; font-weight: bold; }
        .btn-vulnerable { background: #dc2626; color: white; }
        .btn-secure { background: #16a34a; color: white; }
    </style>
</head>
<body>

    <h1>Phase 4-3: プロキシヘッダーと信頼性境界演習</h1>
    <p>リバースプロキシ環境における <code>X-Forwarded-For</code> 偽装によるIP制限バイパス脆弱性を体験・防御します。</p>

    <!-- モード切り替え -->
    <div class="card">
        <h3>現在の判定モード:
            <?php if ($mode === 'vulnerable'): ?>
                <span class="badge badge-vulnerable">モード A: 脆弱 (Vulnerable)</span>
            <?php else: ?>
                <span class="badge badge-secure">モード B: 安全 (Secure)</span>
            <?php endif; ?>
        </h3>
        <p>
            モード切り替え:
            <a href="?mode=vulnerable" class="btn btn-vulnerable" style="<?= $mode === 'vulnerable' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード A (脆弱) に切替</a>
            <a href="?mode=secure" class="btn btn-secure" style="<?= $mode === 'secure' ? 'opacity:0.6; pointer-events:none;' : '' ?>">モード B (安全) に切替</a>
        </p>
    </div>

    <!-- サーバーが受信した生ヘッダー状況 -->
    <div class="card">
        <h3>🌐 サーバーが受信した接続情報とヘッダー</h3>
        <table>
            <tr>
                <th>直前のTCP接続元 (<code>$_SERVER['REMOTE_ADDR']</code>)</th>
                <td><code><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '(未設定)', ENT_QUOTES, 'UTF-8') ?></code></td>
            </tr>
            <tr>
                <th>受信した <code>X-Forwarded-For</code> ヘッダー</th>
                <td>
                    <?php if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])): ?>
                        <strong style="color: #dc2626;"><?= htmlspecialchars($_SERVER['HTTP_X_FORWARDED_FOR'], ENT_QUOTES, 'UTF-8') ?></strong>
                    <?php else: ?>
                        <em style="color: #94a3b8;">(ヘッダーなし)</em>
                    <?php endif; ?>
                </td>
            </tr>
            <tr>
                <th>判定されたクライアントIP</th>
                <td><strong style="font-size: 1.1em; color: #2563eb;"><?= htmlspecialchars($detectedIp, ENT_QUOTES, 'UTF-8') ?></strong></td>
            </tr>
            <tr>
                <th>アクセス許可の社内IP定義</th>
                <td><code><?= ALLOWED_INTERNAL_IP ?></code></td>
            </tr>
        </table>
    </div>

    <!-- ブラウザから試せる攻撃・アクセスシミュレーター -->
    <div class="card" style="border: 2px solid #3b82f6;">
        <h3 style="color: #1d4ed8; margin-top: 0;">🎯 プロキシ環境・ヘッダーシミュレーター</h3>
        <p>外部からの直接アクセスや、正規プロキシ経由でのヘッダー偽造攻撃をシミュレートできます：</p>

        <!-- プリセットボタン群 -->
        <div style="display: flex; flex-direction: column; gap: 8px; margin-bottom: 15px;">
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&simulated_xff=192.168.100.50&simulated_remote=192.168.107.1" class="btn" style="background: #ef4444; color: white;">
                    🚨 攻撃A: 外部直接アクセス偽装 (REMOTE: 外部IP / XFF: 社内IP)
                </a>
                <a href="?mode=<?= $mode ?>&simulated_xff=192.168.100.50,%20203.0.113.1&simulated_remote=127.0.0.1" class="btn" style="background: #dc2626; color: white;">
                    🚨 攻撃B: 正規プロキシ経由の偽造 (REMOTE: 127.0.0.1 / XFF: 社内IP, 攻撃者IP)
                </a>
            </div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <a href="?mode=<?= $mode ?>&simulated_xff=192.168.100.50&simulated_remote=127.0.0.1" class="btn" style="background: #10b981; color: white;">
                    🏢 正規アクセス: 社内プロキシ経由 (REMOTE: 127.0.0.1 / XFF: 社内IP)
                </a>
                <a href="?mode=<?= $mode ?>&simulated_xff=&simulated_remote=" class="btn" style="background: #64748b; color: white;">
                    ⚪ リセット (通常アクセスに戻す)
                </a>
            </div>
        </div>

        <!-- 自由入力フォーム -->
        <form method="GET" style="background: #f1f5f9; padding: 12px; border-radius: 6px;">
            <input type="hidden" name="mode" value="<?= htmlspecialchars($mode, ENT_QUOTES, 'UTF-8') ?>">
            <div style="margin-bottom: 8px;">
                <label><strong>X-Forwarded-For ヘッダー値:</strong></label>
                <input type="text" name="simulated_xff" value="<?= htmlspecialchars($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="例: 192.168.100.50" style="width: 60%; padding: 6px;">
            </div>
            <div style="margin-bottom: 8px;">
                <label><strong>接続元 REMOTE_ADDR:</strong></label>
                <input type="text" name="simulated_remote" value="<?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?>" placeholder="例: 127.0.0.1" style="width: 60%; padding: 6px;">
                <small style="color: #64748b;">(※ 信頼できるプロキシ: <?= implode(', ', TRUSTED_PROXIES) ?>)</small>
            </div>
            <button type="submit" class="btn" style="background: #2563eb; color: white; cursor: pointer; border: none;">この条件でシミュレート</button>
        </form>
    </div>

    <!-- 社内管理画面（判定結果エリア） -->
    <div class="card">
        <h3>🏢 社内極秘管理画面</h3>
        <?php if ($isAllowed): ?>
            <div class="alert alert-success">
                <h4>🎉 認証成功！社内ネットワークからのアクセスと判定されました</h4>
                <p><strong>機密データ:</strong> 社員給与データベース、インフラルートパスワード一覧 (アクセス許可中)</p>
                <?php
                    $isTrustedRemote = in_array($_SERVER['REMOTE_ADDR'] ?? '', TRUSTED_PROXIES, true);
                    $hasXff = !empty($_SERVER['HTTP_X_FORWARDED_FOR']);
                    $xffList = $hasXff ? array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])) : [];
                    $lastXff = !empty($xffList) ? end($xffList) : null;
                ?>
                <?php if ($hasXff): ?>
                    <?php if (!$isTrustedRemote): ?>
                        <p style="color: #dc2626; font-weight: bold; background: #fee2e2; padding: 8px; border-radius: 4px;">
                            🚨 【脆弱性警告】信頼できない外部接続元 (<?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?>) からの偽装 X-Forwarded-For ヘッダーによってIP制限がバイパスされました！
                        </p>
                    <?php elseif ($lastXff !== ALLOWED_INTERNAL_IP): ?>
                        <p style="color: #dc2626; font-weight: bold; background: #fee2e2; padding: 8px; border-radius: 4px;">
                            🚨 【脆弱性警告】多段プロキシ偽装（先頭の偽装IPを誤採用）によりIP制限がバイパスされました！(末尾の真のIP: <?= htmlspecialchars($lastXff ?? '', ENT_QUOTES, 'UTF-8') ?>)
                        </p>
                    <?php else: ?>
                        <p style="color: #166534; font-weight: bold; background: #dcfce7; padding: 8px; border-radius: 4px;">
                            ✅ 【正規アクセス】信頼できる社内プロキシ (<?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?>) を経由した正当な社内アクセスです。
                        </p>
                    <?php endif; ?>
                <?php else: ?>
                    <p style="color: #166534; font-weight: bold; background: #dcfce7; padding: 8px; border-radius: 4px;">
                        ✅ 【正規アクセス】社内IPから直接接続された正当なアクセスです。
                    </p>
                <?php endif; ?>
            </div>
        <?php else: ?>
            <?php
                $isTrustedRemote = in_array($_SERVER['REMOTE_ADDR'] ?? '', TRUSTED_PROXIES, true);
                $hasXff = !empty($_SERVER['HTTP_X_FORWARDED_FOR']);
                $xffList = $hasXff ? array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])) : [];
                $lastXff = !empty($xffList) ? end($xffList) : null;
                $isAttackDefended = ($mode === 'secure' && $hasXff);
            ?>
            <div class="alert alert-danger">
                <?php if ($isAttackDefended): ?>
                    <h4>⛔ 403 Forbidden: 攻撃を安全にブロックしました</h4>
                    <p>最終的に解決された接続元IP (<code><?= htmlspecialchars($detectedIp, ENT_QUOTES, 'UTF-8') ?></code>) は社内許可IPではないため、管理画面への侵入を阻止しました。</p>

                    <?php if (!$isTrustedRemote): ?>
                        <div style="background: #fff1f2; border: 1px solid #fda4af; padding: 12px; border-radius: 6px; margin-top: 10px; color: #9f1239;">
                            <strong style="font-size: 1.05em;">🛡️ 【防御成功: 信頼境界（Trust Boundary）の防壁】</strong><br>
                            直前の接続元 (<code><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?></code>) は信頼できるプロキシではありません。<br>
                            外部から送られた <code>X-Forwarded-For: <?= htmlspecialchars($_SERVER['HTTP_X_FORWARDED_FOR'], ENT_QUOTES, 'UTF-8') ?></code> を完全に無視し、実際の接続元IPで判定したためアクセスを安全に遮断しました！
                        </div>
                    <?php elseif ($lastXff !== ALLOWED_INTERNAL_IP): ?>
                        <div style="background: #fff1f2; border: 1px solid #fda4af; padding: 12px; border-radius: 6px; margin-top: 10px; color: #9f1239;">
                            <strong style="font-size: 1.05em;">🛡️ 【防御成功: 多段プロキシヘッダー検証】</strong><br>
                            接続元は信頼できるプロキシ (<code><?= htmlspecialchars($_SERVER['REMOTE_ADDR'] ?? '', ENT_QUOTES, 'UTF-8') ?></code>) ですが、プロキシが記録した末尾の真のクライアントIP (<code><?= htmlspecialchars($lastXff, ENT_QUOTES, 'UTF-8') ?></code>) は社内IPではありません。<br>
                            先頭の偽装IPを無視し、プロキシが追記した末尾の真のIPに基づいてアクセスを安全に遮断しました！
                        </div>
                    <?php endif; ?>
                <?php else: ?>
                    <h4>⛔ 403 Forbidden: アクセス拒否</h4>
                    <p>あなたの接続元IP (<code><?= htmlspecialchars($detectedIp, ENT_QUOTES, 'UTF-8') ?></code>) からは社内管理画面にアクセスできません（社内専用 / 許可IP: <code><?= ALLOWED_INTERNAL_IP ?></code>）。</p>
                    <p style="color: #64748b; font-size: 0.9em; margin-top: 5px;">
                        ※ 社外ネットワーク（または非許可IP）からの通常アクセスとして正しく遮断されています。
                    </p>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <!-- 攻撃実証ガイド -->
    <div class="card">
        <h3>💻 ターミナルからの攻撃実証 (curl)</h3>
        <p>攻撃者は <code>-H "X-Forwarded-For: 192.168.100.50"</code> を付与してリクエストを送信します：</p>

        <p><strong>① モード A (脆弱) に対する攻撃（社内管理画面が突破されるか確認）:</strong></p>
        <pre>curl -s -H "X-Forwarded-For: 192.168.100.50" "http://localhost:8080/phase4/4-3_proxy_ip_lab.php?mode=vulnerable" | grep -A 2 "認証成功"</pre>

        <p><strong>② モード B (安全) に対する攻撃（偽造ヘッダーが弾かれるか確認）:</strong></p>
        <pre>curl -s -H "X-Forwarded-For: 192.168.100.50" "http://localhost:8080/phase4/4-3_proxy_ip_lab.php?mode=secure" | grep -A 2 "403 Forbidden"</pre>
    </div>

</body>
</html>
