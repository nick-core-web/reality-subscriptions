#!/usr/bin/env python3

import sys
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit


# Параметры, которые разрешены независимо от security/transport.
COMMON_PARAMS = {
    "encryption",
    "security",
    "type",
    "flow",
    "sni",
    "fp",
    "alpn",
}


# Reality-specific.
REALITY_PARAMS = {
    "pbk",
    "sid",
    "spx",
}


# WebSocket-specific.
WS_PARAMS = {
    "path",
    "host",
}


# gRPC-specific.
GRPC_PARAMS = {
    "serviceName",
    "mode",
}


# TCP/RAW-specific.
TCP_PARAMS = {
    "headerType",
}


SUPPORTED_SECURITY = {
    "tls",
    "reality",
}

SUPPORTED_TRANSPORTS = {
    "tcp",
    "ws",
    "grpc",
}


def parse_vless(line):
    """
    Разбирает VLESS URI.
    Возвращает:
        parsed URI
        dict query parameters
    либо None при ошибке.
    """
    line = line.strip()

    if not line or not line.lower().startswith("vless://"):
        return None

    try:
        parsed = urlsplit(line)

        if not parsed.username:
            return None

        if not parsed.hostname:
            return None

        if parsed.port is None:
            return None

        params = dict(
            parse_qsl(
                parsed.query,
                keep_blank_values=False
            )
        )

        return parsed, params

    except (ValueError, UnicodeError):
        return None


def get_transport(params):
    """
    Нормализует transport/network.
    """
    transport = params.get("type")

    if not transport:
        transport = params.get("network")

    if not transport:
        transport = "tcp"

    transport = transport.lower()

    aliases = {
        "raw": "tcp",
        "tcp": "tcp",
        "ws": "ws",
        "websocket": "ws",
        "grpc": "grpc",
    }

    return aliases.get(transport)


def sanitize(parsed, params):
    """
    Создаёт НОВУЮ VLESS-ссылку только из разрешённых параметров.
    Исходная query string никогда не используется.
    """

    security = params.get("security", "").lower()

    if security not in SUPPORTED_SECURITY:
        return None

    transport = get_transport(params)

    if transport not in SUPPORTED_TRANSPORTS:
        return None

    # Начинаем с пустого набора.
    cleaned = {}

    # Общие параметры.
    for key in COMMON_PARAMS:
        if key in params and params[key]:
            cleaned[key] = params[key]

    # Принудительно нормализуем.
    cleaned["security"] = security
    cleaned["type"] = transport

    # -------------------------
    # Reality
    # -------------------------

    if security == "reality":

        # Reality без public key и short ID
        # не является полноценным Reality-профилем.
        if not params.get("pbk"):
            return None

        if not params.get("sid"):
            return None

        for key in REALITY_PARAMS:
            if key in params and params[key]:
                cleaned[key] = params[key]

    # -------------------------
    # Transport
    # -------------------------

    if transport == "ws":

        for key in WS_PARAMS:
            if key in params and params[key]:
                cleaned[key] = params[key]

    elif transport == "grpc":

        for key in GRPC_PARAMS:
            if key in params and params[key]:
                cleaned[key] = params[key]

    elif transport == "tcp":

        for key in TCP_PARAMS:
            if key in params and params[key]:
                cleaned[key] = params[key]

    # -------------------------
    # TLS / Reality server name
    # -------------------------

    # Для TLS/Reality нам нужен SNI.
    if not cleaned.get("sni"):
        return None

    # -------------------------
    # Важный момент:
    #
    # Здесь НЕТ копирования исходных params целиком.
    # Поэтому любые:
    #
    # allowInsecure
    # pinnedPeerCertificate...
    # unknown_parameter
    # и т.п.
    #
    # физически не могут попасть в результат.
    # -------------------------

    # Устанавливаем предсказуемый порядок.
    order = [
        "encryption",
        "security",
        "type",
        "sni",
        "fp",
        "alpn",
        "flow",
        "pbk",
        "sid",
        "spx",
        "path",
        "host",
        "serviceName",
        "mode",
        "headerType",
    ]

    ordered = {}

    for key in order:
        if key in cleaned:
            ordered[key] = cleaned[key]

    # UUID находится в username.
    username = parsed.username

    # Корректно обрабатываем IPv6.
    hostname = parsed.hostname

    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    netloc = f"{username}@{hostname}:{parsed.port}"

    query = urlencode(ordered, doseq=True)

    # Fragment — имя ноды.
    # Он не является параметром подключения.
    result = urlunsplit((
        "vless",
        netloc,
        parsed.path,
        query,
        parsed.fragment,
    ))

    return result


def process_file(input_file, output_file):
    seen = set()
    output = []

    with open(
        input_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as source:

        for line in source:

            parsed = parse_vless(line)

            if not parsed:
                continue

            uri, params = parsed

            cleaned = sanitize(uri, params)

            if not cleaned:
                continue

            # Дедупликация.
            if cleaned in seen:
                continue

            seen.add(cleaned)
            output.append(cleaned)

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as destination:

        if output:
            destination.write(
                "\n".join(output) + "\n"
            )

    print(
        f"{input_file}: "
        f"{len(output)} safe TLS/Reality profiles "
        f"-> {output_file}"
    )


def main():
    if len(sys.argv) != 3:
        print(
            "Usage: sanitize_vless.py INPUT OUTPUT",
            file=sys.stderr
        )
        sys.exit(1)

    process_file(
        sys.argv[1],
        sys.argv[2]
    )


if __name__ == "__main__":
    main()
