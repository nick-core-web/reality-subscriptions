#!/usr/bin/env python3

import json
import re
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit


# ============================================================
# Top-level VLESS query whitelist
# ============================================================

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
    "extra",
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
    "extra",
]


SUPPORTED_SECURITY = {
    "tls",
    "reality",
}


# ============================================================
# XHTTP extra whitelist
#
# Deliberately NOT included:
#   host
#   path
#   mode
#   downloadSettings
#   nested extra
#
# host/path/mode are controlled by the outer XHTTP config in
# Xray's extra processing, while downloadSettings/nested extra
# would introduce another configuration tree.
# ============================================================

XHTTP_EXTRA_KEYS = {
    "headers",

    "xPaddingBytes",
    "xPaddingObfsMode",
    "xPaddingKey",
    "xPaddingHeader",
    "xPaddingPlacement",
    "xPaddingMethod",

    "uplinkHTTPMethod",

    "sessionIDPlacement",
    "sessionIDKey",
    "sessionIDTable",
    "sessionIDLength",

    "seqPlacement",
    "seqKey",

    "uplinkDataPlacement",
    "uplinkDataKey",
    "uplinkChunkSize",

    "noGRPCHeader",
    "noSSEHeader",

    "scMaxEachPostBytes",
    "scMinPostsIntervalMs",
    "scMaxBufferedPosts",
    "scStreamUpServerSecs",

    "serverMaxHeaderBytes",

    "xmux",
}


XHTTP_XMUX_KEYS = {
    "maxConcurrency",
    "maxConnections",
    "cMaxReuseTimes",
    "hMaxRequestTimes",
    "hMaxReusableSecs",
    "hKeepAlivePeriod",
}


XHTTP_MODES = {
    "auto",
    "packet-up",
    "stream-up",
    "stream-one",
}


XHTTP_PADDING_PLACEMENTS = {
    "cookie",
    "header",
    "query",
    "queryInHeader",
}


XHTTP_PADDING_METHODS = {
    "repeat-x",
    "tokenish",
}


XHTTP_SESSION_PLACEMENTS = {
    "path",
    "cookie",
    "header",
    "query",
}


XHTTP_SEQ_PLACEMENTS = {
    "path",
    "cookie",
    "header",
    "query",
}


XHTTP_UPLINK_DATA_PLACEMENTS = {
    "auto",
    "body",
    "cookie",
    "header",
}


# Xray currently recognizes these predefined session tables.
PREDEFINED_SESSION_TABLES = {
    "ALPHABET",
    "Alphabet",
    "BASE36",
    "Base62",
    "HEX",
    "alphabet",
    "base36",
    "hex",
    "number",
}


# ============================================================
# Security / structural limits
# ============================================================

MAX_EXTRA_BYTES = 16 * 1024

MAX_EXTRA_STRING_LENGTH = 4096
MAX_HEADER_COUNT = 64
MAX_HEADER_NAME_LENGTH = 256
MAX_HEADER_VALUE_LENGTH = 4096

MAX_SESSION_TABLE_LENGTH = 256

# Maximum number of values in a numeric range.
# This is a sanitizer resource-safety limit, not an XHTTP
# protocol requirement.
MAX_RANGE_WIDTH = 1_000_000


# HTTP token, RFC-style conservative validation.
HTTP_TOKEN_RE = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$"
)


# ============================================================
# Generic helpers
# ============================================================

def has_control_chars(value):
    return any(
        ord(char) < 0x20 or ord(char) == 0x7f
        for char in value
    )


def valid_string(value, max_length=MAX_EXTRA_STRING_LENGTH):
    return (
        isinstance(value, str)
        and value != ""
        and len(value) <= max_length
        and not has_control_chars(value)
    )


def is_empty_json_value(value):
    return value is None or value == ""


def parse_int32_range(value):
    """
    Accept the same basic forms used by Xray's Int32Range:

        123
        "123"
        "100-1000"

    We deliberately reject negative values here.

    Returns:
        (from_value, to_value)
        or None
    """

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        number = value

        if number < 0 or number > 2_147_483_647:
            return None

        return number, number

    if not isinstance(value, str):
        return None

    if value == "":
        return None

    if has_control_chars(value):
        return None

    if len(value) > 64:
        return None

    match = re.fullmatch(
        r"([0-9]+)(?:-([0-9]+))?",
        value
    )

    if not match:
        return None

    left = int(match.group(1))

    if left > 2_147_483_647:
        return None

    if match.group(2) is None:
        right = left
    else:
        right = int(match.group(2))

        if right > 2_147_483_647:
            return None

    if left > right:
        left, right = right, left

    if right - left > MAX_RANGE_WIDTH:
        return None

    return left, right


def canonicalize_range(value):
    parsed = parse_int32_range(value)

    if parsed is None:
        return None

    left, right = parsed

    if left == right:
        return str(left)

    return f"{left}-{right}"


def parse_nonnegative_int64(value):
    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        number = value
    elif isinstance(value, str):
        if not re.fullmatch(r"[0-9]+", value):
            return None

        if len(value) > 32:
            return None

        number = int(value)
    else:
        return None

    if number < 0 or number > 9_223_372_036_854_775_807:
        return None

    return number


# ============================================================
# Specific XHTTP validators
# ============================================================

def sanitize_headers(value):
    if not isinstance(value, dict):
        return None

    if len(value) > MAX_HEADER_COUNT:
        return None

    result = {}

    for name, header_value in value.items():

        if not isinstance(name, str):
            continue

        if not isinstance(header_value, str):
            continue

        if not valid_string(
            name,
            MAX_HEADER_NAME_LENGTH
        ):
            continue

        if not valid_string(
            header_value,
            MAX_HEADER_VALUE_LENGTH
        ):
            continue

        # Xray explicitly rejects Host in XHTTP headers.
        if name.lower() == "host":
            continue

        # Prevent malformed/injection-style header names.
        if not HTTP_TOKEN_RE.fullmatch(name):
            continue

        result[name] = header_value

    return result


def sanitize_session_table(value):
    if not valid_string(
        value,
        MAX_SESSION_TABLE_LENGTH
    ):
        return None

    if value in PREDEFINED_SESSION_TABLES:
        return value

    # Xray requires ASCII for custom session tables.
    if any(ord(char) >= 0x80 for char in value):
        return None

    return value


def validate_session_configuration(result):
    """
    Xray requires:
        sessionIDLength > 0
        when sessionIDTable is specified.

    It also checks that the table/length combination has enough
    possible IDs.
    """

    table = result.get("sessionIDTable")
    length = result.get("sessionIDLength")

    if table is None:
        return True

    if length is None:
        return False

    parsed = parse_int32_range(length)

    if parsed is None:
        return False

    min_length, max_length = parsed

    if min_length <= 0:
        return False

    # Conservative calculation with an early cutoff.
    if table in PREDEFINED_SESSION_TABLES:
        table_sizes = {
            "ALPHABET": 26,
            "Alphabet": 52,
            "BASE36": 36,
            "Base62": 62,
            "HEX": 16,
            "alphabet": 26,
            "base36": 36,
            "hex": 16,
            "number": 10,
        }

        table_size = table_sizes[table]
    else:
        table_size = len(table)

    # We only need to establish that there are at least
    # 2^31-ish possible combinations, matching Xray's intent.
    #
    # Avoid giant exponentiation.
    required = 2_147_483_648

    possibilities = 1

    for _ in range(max_length):
        possibilities *= table_size

        if possibilities >= required:
            break

    if possibilities < required:
        return False

    return True


def sanitize_xmux(value):
    if not isinstance(value, dict):
        return None

    result = {}

    for key, raw_value in value.items():

        if key not in XHTTP_XMUX_KEYS:
            continue

        if key == "hKeepAlivePeriod":
            number = parse_nonnegative_int64(raw_value)

            if number is None:
                continue

            result[key] = number
            continue

        canonical = canonicalize_range(raw_value)

        if canonical is None:
            continue

        result[key] = canonical

    # Xray rejects positive maxConnections together with
    # positive maxConcurrency.
    max_connections = parse_int32_range(
        result["maxConnections"]
    ) if "maxConnections" in result else None

    max_concurrency = parse_int32_range(
        result["maxConcurrency"]
    ) if "maxConcurrency" in result else None

    if (
        max_connections is not None
        and max_concurrency is not None
        and max_connections[1] > 0
        and max_concurrency[1] > 0
    ):
        # Keep maxConnections and remove the conflicting
        # maxConcurrency. This gives deterministic output.
        del result["maxConcurrency"]

    return result


def sanitize_xhttp_extra(raw_extra, outer_mode):
    """
    Returns:
        sanitized JSON string
        or None if extra should be removed entirely.
    """

    if not isinstance(raw_extra, str):
        return None

    if len(raw_extra.encode("utf-8")) > MAX_EXTRA_BYTES:
        return None

    try:
        data = json.loads(raw_extra)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None

    if not isinstance(data, dict):
        return None

    result = {}

    for key, value in data.items():

        # Explicit allowlist.
        if key not in XHTTP_EXTRA_KEYS:
            continue

        # Empty strings and nulls carry no useful configuration.
        if is_empty_json_value(value):
            continue

        # ----------------------------------------------------
        # headers
        # ----------------------------------------------------
        if key == "headers":
            sanitized = sanitize_headers(value)

            if sanitized:
                result[key] = sanitized

            continue

        # ----------------------------------------------------
        # Boolean parameters
        # ----------------------------------------------------
        if key in {
            "xPaddingObfsMode",
            "noGRPCHeader",
            "noSSEHeader",
        }:
            if isinstance(value, bool):
                result[key] = value

            continue

        # ----------------------------------------------------
        # Enum/string parameters
        # ----------------------------------------------------
        if key == "xPaddingPlacement":
            if (
                isinstance(value, str)
                and value in XHTTP_PADDING_PLACEMENTS
            ):
                result[key] = value

            continue

        if key == "xPaddingMethod":
            if (
                isinstance(value, str)
                and value in XHTTP_PADDING_METHODS
            ):
                result[key] = value

            continue

        if key == "sessionIDPlacement":
            if (
                isinstance(value, str)
                and value in XHTTP_SESSION_PLACEMENTS
            ):
                result[key] = value

            continue

        if key == "seqPlacement":
            if (
                isinstance(value, str)
                and value in XHTTP_SEQ_PLACEMENTS
            ):
                result[key] = value

            continue

        if key == "uplinkDataPlacement":
            if (
                isinstance(value, str)
                and value in XHTTP_UPLINK_DATA_PLACEMENTS
            ):
                result[key] = value

            continue

        # ----------------------------------------------------
        # uplinkHTTPMethod
        #
        # Xray uppercases it. GET is only valid in packet-up.
        # Other HTTP methods are kept as HTTP-token strings.
        # ----------------------------------------------------
        if key == "uplinkHTTPMethod":

            if not isinstance(value, str):
                continue

            if not valid_string(value, 32):
                continue

            method = value.upper()

            if not HTTP_TOKEN_RE.fullmatch(method):
                continue

            if method == "GET" and outer_mode != "packet-up":
                continue

            result[key] = method
            continue

        # ----------------------------------------------------
        # sessionIDTable
        # ----------------------------------------------------
        if key == "sessionIDTable":
            sanitized = sanitize_session_table(value)

            if sanitized is not None:
                result[key] = sanitized

            continue

        # ----------------------------------------------------
        # String keys
        # ----------------------------------------------------
        if key in {
            "xPaddingKey",
            "xPaddingHeader",
            "sessionIDKey",
            "seqKey",
            "uplinkDataKey",
        }:
            if valid_string(value):
                result[key] = value

            continue

        # ----------------------------------------------------
        # Int32Range parameters
        # ----------------------------------------------------
        if key in {
            "xPaddingBytes",
            "sessionIDLength",
            "uplinkChunkSize",
            "scMaxEachPostBytes",
            "scMinPostsIntervalMs",
            "scStreamUpServerSecs",
        }:
            canonical = canonicalize_range(value)

            if canonical is None:
                continue

            # Xray explicitly rejects xPaddingBytes <= 0
            # when the field is configured.
            if key == "xPaddingBytes":
                left, right = parse_int32_range(canonical)

                if left <= 0 or right <= 0:
                    continue

            result[key] = canonical
            continue

        # ----------------------------------------------------
        # int64 parameter
        # ----------------------------------------------------
        if key == "scMaxBufferedPosts":
            number = parse_nonnegative_int64(value)

            if number is not None:
                result[key] = number

            continue

        # ----------------------------------------------------
        # int32 parameter
        # ----------------------------------------------------
        if key == "serverMaxHeaderBytes":
            number = parse_nonnegative_int64(value)

            if number is None:
                continue

            if number > 2_147_483_647:
                continue

            result[key] = number
            continue

        # ----------------------------------------------------
        # xmux
        # ----------------------------------------------------
        if key == "xmux":
            sanitized = sanitize_xmux(value)

            if sanitized:
                result[key] = sanitized

            continue

    # --------------------------------------------------------
    # Cross-field validation
    # --------------------------------------------------------

    # cookie/header uplink-data placement requires packet-up.
    uplink_placement = result.get(
        "uplinkDataPlacement"
    )

    if uplink_placement in {"cookie", "header"}:
        if outer_mode != "packet-up":
            del result["uplinkDataPlacement"]

    # sessionIDTable requires a valid positive sessionIDLength
    # and sufficient combination space.
    if not validate_session_configuration(result):
        result.pop("sessionIDTable", None)
        result.pop("sessionIDLength", None)

    # If nothing survived sanitization, don't emit an empty extra.
    if not result:
        return None

    sanitized_json = json.dumps(
        result,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )

    if len(sanitized_json.encode("utf-8")) > MAX_EXTRA_BYTES:
        return None

    return sanitized_json


# ============================================================
# VLESS parsing
# ============================================================

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


# ============================================================
# Sanitization
# ============================================================

def sanitize(parsed, pairs):
    security = get_security(pairs)

    if security is None:
        return None

    # Determine outer XHTTP mode before sanitizing extra.
    outer_mode = "auto"

    for name, value in pairs:
        if name == "mode":
            if isinstance(value, str) and value in XHTTP_MODES:
                outer_mode = value
            else:
                outer_mode = "invalid"
                break

    if outer_mode == "invalid":
        # If mode is explicitly present but invalid,
        # remove it rather than making extra depend on it.
        outer_mode = "auto"

    extra_values = [
        value
        for name, value in pairs
        if name == "extra"
    ]

    # --------------------------------------------------------
    # At most one extra.
    #
    # If multiple extras exist, remove ALL extras.
    # The profile itself remains valid.
    # --------------------------------------------------------
    sanitized_extra = None

    if len(extra_values) == 1:
        sanitized_extra = sanitize_xhttp_extra(
            extra_values[0],
            outer_mode,
        )

    filtered = []

    for name, value in pairs:

        if name == "extra":
            continue

        if name not in WHITELIST:
            continue

        if name == "security":
            value = security

        # Empty ordinary query parameters are discarded.
        if value == "":
            continue

        # mode has an explicit XHTTP enum.
        if name == "mode":
            if value not in XHTTP_MODES:
                continue

        filtered.append((name, value))

    if sanitized_extra is not None:
        filtered.append(
            ("extra", sanitized_extra)
        )

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
        netloc = (
            f"{username}@{hostname}:{parsed.port}"
        )
    else:
        netloc = (
            f"{username}@{hostname}"
        )

    query = urlencode(
        result,
        doseq=True,
    )

    return urlunsplit((
        "vless",
        netloc,
        parsed.path,
        query,
        parsed.fragment,
    ))


# ============================================================
# File processing
# ============================================================

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
        errors="ignore",
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
                pairs,
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
        encoding="utf-8",
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
            file=sys.stderr,
        )
        sys.exit(1)

    process_file(
        sys.argv[1],
        sys.argv[2],
    )


if __name__ == "__main__":
    main()
