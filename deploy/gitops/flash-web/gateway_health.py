"""Normalize only the canonical shared gateway's availability decisions."""
import re


def update(content, health_hostname):
    if not re.fullmatch(r'[a-z0-9.-]+', health_hostname):
        raise ValueError('invalid gateway health hostname')
    pattern = rb'(?m)^[ \t]*\(heterocloud_envoy\)[ \t]*\{'
    matches = list(re.finditer(pattern, content))
    if len(matches) != 1:
        raise ValueError('ambiguous shared gateway definition')
    start = matches[0].end()
    depth = 1
    quoted = False
    escaped = False
    comment = False
    end = start
    while end < len(content) and depth:
        value = content[end]
        if comment:
            if value == 10:
                comment = False
        elif escaped:
            escaped = False
        elif value == 92:
            escaped = True
        elif value == 34:
            quoted = not quoted
        elif not quoted:
            if value == 35:
                comment = True
            elif value == 123:
                depth += 1
            elif value == 125:
                depth -= 1
        end += 1
    if depth:
        raise ValueError('unclosed shared gateway definition')
    body = content[start:end - 1]
    # Small fixture definitions and non-proxy operator snippets remain untouched.
    if not re.search(rb'(?m)^\s*reverse_proxy\s', body):
        return content
    if len(re.findall(rb'(?m)^\s*reverse_proxy\s', body)) != 1:
        raise ValueError('ambiguous shared gateway proxy')
    # Application HTTP errors are not transport failures. In particular an
    # optional Coder API's 500/502 must not withdraw unrelated working routes.
    body = re.sub(rb'(?m)^[ \t]*unhealthy_status[^\r\n]*\r?\n', b'', body)
    uri = re.compile(rb'(?m)^([ \t]*)health_uri[ \t]+[^\r\n]+')
    if len(uri.findall(body)) != 1:
        raise ValueError('shared gateway health URI missing')
    body = uri.sub(lambda m: m[1] + b'health_uri /healthz', body)
    headers = re.compile(rb'(?m)^([ \t]*)health_headers[ \t]*\{[ \t]*\r?\n([ \t]*)Host[ \t]+[^\r\n]+\r?\n[ \t]*\}')
    if len(headers.findall(body)) != 1:
        raise ValueError('shared gateway health Host missing')
    body = headers.sub(lambda m: m[1] + b'health_headers {\n' + m[2] + b'Host ' + health_hostname.encode() + b'\n' + m[1] + b'}', body)
    # One slow sample must not withdraw a healthy path. This probes Envoy's
    # direct-response route, independent of every tenant and control-plane app.
    body = re.sub(rb'(?m)^[ \t]*health_(?:fails|passes)[^\r\n]*\r?\n', b'', body)
    status = re.compile(rb'(?m)^([ \t]*)health_status[ \t]+[^\r\n]+')
    if len(status.findall(body)) != 1:
        raise ValueError('shared gateway health status missing')
    body = status.sub(lambda m: m[1] + b'health_status 200\n' + m[1] + b'health_fails 3\n' + m[1] + b'health_passes 2', body)
    return content[:start] + body + content[end - 1:]
