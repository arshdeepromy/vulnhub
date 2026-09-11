# Extends the stock wordpress images (apache/Debian or cli/Alpine variant,
# picked via BASE_IMAGE) with the phpredis extension, so WP_REDIS_HOST/
# WP_REDIS_PORT (already defined in docker-compose.yml's shared
# WORDPRESS_CONFIG_EXTRA) actually do something. Without this,
# wp_using_ext_object_cache() is false and WordPress silently falls back to
# its default non-persistent object cache -- fine for a short web request,
# but an unbounded PHP-process-memory leak for a long-running wp-cli sync
# that touches hundreds of thousands of rows (confirmed: OOM-killed at both
# 2g and 4g on a real Tenable account).
#
# wordpress:php8.3-apache is Debian; wordpress:cli-php8.3 is Alpine -- same
# Dockerfile handles both by detecting which package manager is present,
# using $PHPIZE_DEPS (defined by the official php images for exactly this).
ARG BASE_IMAGE=wordpress:php8.3-apache
FROM ${BASE_IMAGE}

USER root

RUN set -eux; \
	if command -v apt-get >/dev/null 2>&1; then \
		apt-get update; \
		apt-get install -y --no-install-recommends $PHPIZE_DEPS; \
		pecl install redis; \
		docker-php-ext-enable redis; \
		apt-get purge -y --auto-remove $PHPIZE_DEPS; \
		rm -rf /var/lib/apt/lists/*; \
	elif command -v apk >/dev/null 2>&1; then \
		apk add --no-cache --virtual .build-deps $PHPIZE_DEPS; \
		pecl install redis; \
		docker-php-ext-enable redis; \
		apk del .build-deps; \
	else \
		echo "Neither apt-get nor apk found in this base image" >&2; \
		exit 1; \
	fi
