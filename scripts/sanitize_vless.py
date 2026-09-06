#!/usr/bin/env python3

import sys
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit


WHITELIST = {
    "encryption",
    "security",
    "type",
    "network",
    "flow",
    "sni",
    "fp",
    "alpn",
    "pbk",
    "sid",
    "spx",
    "host",
    "path",
    "mode",
    "authority",
    "serviceName",
    "mtu",
    "tti",
    "uplinkCapacity",
    "downlinkCapacity",
    "congestion",
    "readBufferSize",
    "writeBufferSize",
}


OUTPUT_ORDER = [
    "encryption",
    "security",
    "type",
    "network",
    "flow",
    "sni",
    "fp",
    "alpn",
    "pbk",
    "sid",
    "spx",
    "host",
    "path",
    "mode",
    "authority",
    "serviceName",
    "mtu",
    "tti",
    "uplinkCapacity",
    "downlinkCapacity",
    "congestion",
    "readBufferSize",
    "writeBufferSize",
]


SUPPORTED_SECURITY = {
    "tls",
    "reality",
}


def parse_vless(line):
    line = line.strip()

    if not line:
        return None

    if not line.lower().startswith("vless://"):
        return None

    try:
        parsed = urlsplit(line)

        if not parsed.username:
            return None

        if not parsed.hostname:
            return None

        if parsed.port is None:
            return None

        raw_pairs = parse_qsl(
            parsed.query,
            keep_blank_values=False
        )

        pairs = [
            (
                "security" if name.lower() == "security" else name,
                value
            )
            for name, value in raw_pairs
        ]

        return parsed, pairs

    except (ValueError, UnicodeError):
        return None


def get_security(pairs):
    values = [
        value.lower()
        for name, value in pairs
        if name == "security"
    ]

    if len(values) != 1:
        return None

    if values[0] not in SUPPORTED_SECURITY:
        return None

    return values[0]


def sanitize(parsed, pairs):
    security = get_security(pairs)

    if security is None:
        return None

    filtered = [
        (
            name,
            security if name == "security" else value
        )
        for name, value in pairs
        if name in WHITELIST
    ]

    result = []

    for key in OUTPUT_ORDER:
        result.extend(
            (name, value)
            for name, value in filtered
            if name == key
        )

    username = parsed.username
    hostname = parsed.hostname

    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"

    if parsed.port is not None:
        netloc = f"{username}@{hostname}:{parsed.port}"
    else:
        netloc = f"{username}@{hostname}"

    query = urlencode(
        result,
        doseq=True
    )

    return urlunsplit((
        "vless",
        netloc,
        parsed.path,
        query,
        parsed.fragment,
    ))


def process_file(input_file, output_file):
    seen = set()
    output = []

    total = 0
    rejected = 0
    duplicates = 0

    with open(
        input_file,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as source:

        for line in source:
            line = line.strip()

            if not line:
                continue

            total += 1

            parsed = parse_vless(line)

            if parsed is None:
                rejected += 1
                continue

            uri, pairs = parsed

            cleaned = sanitize(
                uri,
                pairs
            )

            if cleaned is None:
                rejected += 1
                continue

            if cleaned in seen:
                duplicates += 1
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
        f"{len(output)} profiles written to {output_file}"
    )
    print(f"Input lines: {total}")
    print(f"Rejected: {rejected}")
    print(f"Duplicates: {duplicates}")
    print(f"Output lines: {len(output)}")


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
