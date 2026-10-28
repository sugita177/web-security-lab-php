<?php
/**
 * 社内内部専用API (Internal Admin API)
 * 外部のインターネットからは直接アクセスできず、
 * 社内ネットワーク/コンテナ内部からのみアクセス可能な機密サービス
 */
header('Content-Type: application/json; charset=UTF-8');

echo json_encode([
    'status' => 'success',
    'system' => 'Internal Payroll & Cloud Infrastructure Admin',
    'secret_flag' => 'FLAG{SSRF_INTERNAL_API_LEAKED_SUCCESSFULLY}',
    'database_credentials' => [
        'db_host' => 'mysql',
        'db_user' => 'root',
        'db_pass' => 'root_password',
        'db_name' => 'security_lab'
    ],
    'aws_iam_keys' => [
        'AccessKeyId' => 'AKIAIOSFODNN7EXAMPLE',
        'SecretAccessKey' => 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
        'Token' => 'AQoDYXdzEJr1...EXAMPLETOKEN'
    ],
    'message' => '社内専用機密APIです。外部インターネットへの露出は厳禁です。'
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
