# bindantic

[![PyPI version](https://img.shields.io/pypi/v/bindantic)](https://pypi.org/project/bindantic/)
[![Python versions](https://img.shields.io/pypi/pyversions/bindantic)](https://pypi.org/project/bindantic/)
[![License](https://img.shields.io/github/license/DVSAWR/bindantic)](LICENSE)
[![Coverage](https://img.shields.io/badge/coverage-96%25-brightgreen)](htmlcov/index.html)

**bindantic** - a library for managing **[BIND9](https://bind9.readthedocs.io/en/latest/reference.html)** DNS server configuration via **[Pydantic](https://github.com/pydantic/pydantic)** models.

Instead of manually editing `named.conf` , you describe the configuration in Python, and the library generates correct BIND9 syntax and (optionally) places files into the required directories.


## Features

- **Full support for all `named.conf` blocks:**
    - `acl`, `controls`, `dnssec-policy`, `http`, `key`, `key-store`, `logging`, `options`,
`remote-servers`, `server`, `statistics-channels`, `tls`, `trust-anchors`, `view`, `zone`.
- **All common resource record types:**
    - `A`, `AAAA`, `CAA`, `CERT`, `CNAME`, `DNAME`, `DNSKEY`, `DS`, `HINFO`, `LOC`, `MX`, `NAPTR`, `NSEC`, `NS`, `PTR`, `RP`, `RRSIG`, `SOA`, `SPF`, `SRV`, `SSHFP`, `TLSA`, `TXT`.
- **Built-in validation** - pass strings, numbers, IP addresses, durations – the library will format them correctly for BIND.
- **Syntax generation in one line**
    - `model.model_bind_syntax()` - for any block or the whole `named.conf`,
    - `zone.model_bind_syntax_zone_file()` - for a ready-to-use zone file.
- **Generate files without writing / write to disk**
    - `config.generate_files()` - returns a list of generated files
    - `config.write_files("./my_config")` - creates `named.conf`, zones, keys, DNSSEC policies and organises them into subdirectories.
- **Python** - 3.10+, static typing, 96% test coverage.
- **No extra dependencies** - only Pydantic


## Installation

```bash
pip install bindantic
```

## ⚠️ NOTE:

The  `named-checkconf` utility from the `bind-utils` package may be older than your BIND server and may not recognise new directives.

**bindantic** generates syntax according to the latest stable BIND 9.20.x version. If you check the configuration with an older utility you may get errors. Always use the same version of `named-checkconf` as your server, if possible.

## Quick Start

Example of a minimal configuration

```python
from bindantic import (
    ARecord,
    NamedConfig,
    NSRecord,
    OptionsBlock,
    SOARecord,
    ZoneBlock,
    ZoneTypeEnum,
)

config = NamedConfig(
    options_block=OptionsBlock(
        directory="/etc/bind",
        recursion=True,
        allow_recursion=["localhost", "localnets"],
        listen_on=["any"],
        listen_on_v6=["any"],
    ),
    zone_blocks=[
        ZoneBlock(
            comment="optional comment",
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="zones/example.com.zone",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2026010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                    origin="example.com",
                    ttl=3600,
                ),
                NSRecord(nsdname="ns1.example.com", comment="optional comment"),
                ARecord(name="@", address="192.168.1.1"),
            ],
        )
    ],
)
```

<details> <summary> Output of `config.model_bind_syntax()` </summary>

```txt
options {
    allow-recursion {
        localhost;
        localnets;
    };
    directory "/etc/bind";
    listen-on {
        any;
    };
    listen-on-v6 {
        any;
    };
    recursion yes;
};

# optional comment
zone example.com. {
    type primary;
    file "zones/example.com.zone";
};
```
</details>

<details> <summary> Output of `config.zone_blocks[0].model_bind_syntax_zone_file()` </summary>

```txt
$TTL 3600
$ORIGIN example.com.
@                    IN   SOA ns1.example.com. admin.example.com. (
                                     2026010101 ; Serial number (YYYYMMDDNN)
                                     10800      ; Refresh time
                                     3600       ; Retry time
                                     604800     ; Expire time
                                     3600       ; Minimum TTL
                     )
@                    IN   NS         ns1.example.com. ; optional comment
@                    IN   A          192.168.1.1
```
</details>

<details> <summary> Output of `config.generate_files()` </summary>

```txt
[
    GeneratedFile(
        path=PosixPath("/etc/bind/zones/example.com.zone"),
        content="<CONTENT>",
        type="zone",
    ),
    GeneratedFile(
        path=PosixPath("/etc/bind/named.conf"),
        content="<CONTENT>",
        type="config",
    ),
]
```
</details>

<details> <summary> Output of `config.write_files(base_dir="./examples/example")` </summary>

```txt
example_bind/
├── named.conf
└── zones/
    └── example.com.zone
```

```
# Automatically generated by bindantic - please adjust!

options {
    allow-recursion {
        localhost;
        localnets;
    };
    directory "examples/example";
    listen-on {
        any;
    };
    listen-on-v6 {
        any;
    };
    recursion yes;
};

# optional comment
zone example.com. {
    type primary;
    file "zones/example.com.zone";
};
```

```txt
$TTL 3600
$ORIGIN example.com.
@                    IN   SOA ns1.example.com. admin.example.com. (
                                     2026010101 ; Serial number (YYYYMMDDNN)
                                     10800      ; Refresh time
                                     3600       ; Retry time
                                     604800     ; Expire time
                                     3600       ; Minimum TTL
                     )
@                    IN   NS         ns1.example.com. ; optional comment
@                    IN   A          192.168.1.1
```
</details>

\
The file [./examples/manual_example.py](./examples/manual_example.py) contains usage examples for all supported models.

