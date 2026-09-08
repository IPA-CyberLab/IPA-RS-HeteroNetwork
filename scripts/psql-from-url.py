#!/usr/bin/env python3
"""Run psql using DATABASE_URL without placing credentials in process arguments."""

import os
import sys
from urllib.parse import parse_qsl, unquote, urlsplit


def main():
    environment = os.environ.copy()
    value = environment.pop("DATABASE_URL", "")
    try:
        url = urlsplit(value)
        valid = url.scheme in ("postgres", "postgresql") and url.hostname and url.path[1:]
        if not valid or url.fragment or not url.username:
            raise ValueError("invalid URL")
        environment.update({
            "PGHOST": url.hostname,
            "PGPORT": str(url.port or 5432),
            "PGUSER": unquote(url.username),
            "PGPASSWORD": unquote(url.password or ""),
            "PGDATABASE": unquote(url.path[1:]),
            "PGCONNECT_TIMEOUT": "10",
        })
        parameters = {
            "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
            "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY",
            "connect_timeout": "PGCONNECT_TIMEOUT", "application_name": "PGAPPNAME",
            "target_session_attrs": "PGTARGETSESSIONATTRS",
        }
        for name, setting in parse_qsl(url.query, strict_parsing=True):
            if name not in parameters:
                raise ValueError("unsupported URL parameter")
            environment[parameters[name]] = setting
    except ValueError:
        raise SystemExit("DATABASE_URL must be a supported PostgreSQL URI; credentials were not logged")
    os.execvpe("psql", ["psql", "-X", *sys.argv[1:]], environment)


if __name__ == "__main__":
    main()
