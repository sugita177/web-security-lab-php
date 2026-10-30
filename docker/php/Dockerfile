FROM php:8.5-fpm-alpine

# PDO MySQL拡張のインストール
RUN docker-php-ext-install pdo_mysql

# 【Phase 5-2 オンデマンド追加】PECL による Redis 拡張のインストールと有効化
RUN apk add --no-cache --virtual .build-deps $PHPIZE_DEPS \
    && pecl install redis \
    && docker-php-ext-enable redis \
    && apk del .build-deps
