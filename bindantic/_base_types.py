from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import Annotated, Any, TypeAlias

from ._base_types_validation import BindTypeCoreSchema, Validator

string_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_string),
]
"""
`<string>`

Data type used to represent textual information such as domain names, file paths,
authentication keys, log channel names, etc. Strings may be quoted or unquoted.
If a string contains spaces, it must be quoted.
"""
quoted_string_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_quoted_string),
]
"""
`<quoted_string>`

A string enclosed in double quotes. Used when the string may contain whitespace
or special characters that would otherwise be interpreted by the parser.
"""
domain_name_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_domain_name),
]
"""
`<domain_name>`

A quoted string which is used as a DNS name; for example: my.test.domain.
"""
dns_name_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_dns_name),
]
"""
A quoted string which is used as a special DNS name; for example: _sip._tcp.
"""
server_key_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_server_key),
]
"""
`<server_key>`

A domain_name representing the name of a shared key, to be used for transaction security.
Keys are defined using key blocks.
"""
tls_id_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_tls_id),
]
"""
`<tls_id>`

A named TLS configuration object which defines a TLS key and certificate. See tls block.
"""
boolean_BIND: TypeAlias = Annotated[
    bool | str | int | float,
    BindTypeCoreSchema(Validator.validate_boolean),
]
"""
`<boolean>`

Either yes or no. The words true and false are also accepted, as are the numbers 1 and 0.
"""
integer_BIND: TypeAlias = Annotated[
    int,
    BindTypeCoreSchema(Validator.validate_integer),
]
"""
`<integer>`

A non-negative 32-bit integer (i.e., a number between 0 and 4294967295, inclusive).
Its acceptable value might be further limited by the context in which it is used.
"""
fixed_point_BIND: TypeAlias = Annotated[
    float | int | str,
    BindTypeCoreSchema(Validator.validate_fixedpoint),
]
"""
`<fixedpoint>`

A non-negative real number that can be specified to the nearest one-hundredth.
Up to five digits can be specified before a decimal point, and up to two digits after,
so the maximum value is 99999.99. Acceptable values might be further limited
by the contexts in which they are used.
"""
percentage_BIND: TypeAlias = Annotated[
    str | int | float,
    BindTypeCoreSchema(Validator.validate_percentage),
]
"""
`<percentage>`

An integer value followed by % to represent percent.
"""
duration_BIND: TypeAlias = Annotated[
    int | str,
    BindTypeCoreSchema(Validator.validate_duration),
]
"""
`<duration>`

A duration in BIND 9 can be written in three ways: as a single number representing
seconds, as a string of numbers with TTL-style time-unit suffixes, or in ISO 6801
duration format.

Allowed TTL time-unit suffixes are: "W" (week), "D" (day), "H" (hour), "M" (minute),
and "S" (second). Examples: "1W" (1 week), "3d12h" (3 days, 12 hours).

ISO 8601 duration format consists of the letter "P", followed by an optional series
of numbers with unit suffixes "Y" (year), "M" (month), "W" (week), and "D" (day);
this may optionally be followed by the letter "T", and another series of numbers with
unit suffixes "H" (hour), "M" (minute), and "S" (second).

Examples: "P3M10D" (3 months, 10 days), "P2WT12H" (2 weeks, 12 hours),
"pt15m" (15 minutes). For more information on ISO 8601 duration format, see RFC 3339,
appendix A.

Both TTL-style and ISO 8601 duration formats are case-insensitive.
"""
ip_address_BIND: TypeAlias = Annotated[
    str | IPv4Address | IPv6Address,
    BindTypeCoreSchema(Validator.validate_ip_address),
]
"""
`<ip_address>`

An ipv4_address or ipv6_address.
"""
ip_v4_address_BIND: TypeAlias = Annotated[
    str | IPv4Address,
    BindTypeCoreSchema(Validator.validate_ip_v4_address),
]
"""
`<ipv4_address>`

An IPv4 address with exactly four integer elements valued 0 through 255
and separated by dots (.), such as 192.168.1.1 (a "dotted-decimal" notation with
all four elements present).
"""
ip_v6_address_BIND: TypeAlias = Annotated[
    str | IPv6Address,
    BindTypeCoreSchema(Validator.validate_ip_v6_address),
]
"""
`<ipv6_address>`

An IPv6 address, such as 2001:db8::1234. IPv6-scoped addresses that have ambiguity
on their scope zones must be disambiguated by an appropriate zone ID with the percent
character (%) as a delimiter. It is strongly recommended to use string zone names rather
than numeric identifiers, to be robust against system configuration changes. However,
since there is no standard mapping for such names and identifier values, only interface
names as link identifiers are supported, assuming one-to-one mapping between interfaces
and links. For example, a link-local address fe80::1 on the link attached to the interface
ne0 can be specified as fe80::1%ne0. Note that on most systems link-local addresses
always have ambiguity and need to be disambiguated.
"""
net_prefix_BIND: TypeAlias = Annotated[
    str | IPv4Network | IPv6Network,
    BindTypeCoreSchema(Validator.validate_netprefix),
]
"""
`<netprefix>`

An IP network specified as an ip_address, followed by a slash (/) and then the number
of bits in the netmask. Trailing zeros in an ip_address may be omitted. For example,
127/8 is the network 127.0.0.0 with netmask 255.0.0.0 and 1.2.3.0/28 is network 1.2.3.0
with netmask 255.255.255.240. When specifying a prefix involving an IPv6-scoped address,
the scope may be omitted. In that case, the prefix matches packets from any scope.
"""
port_BIND: TypeAlias = Annotated[
    str | int,
    BindTypeCoreSchema(Validator.validate_port),
]
"""
`<port>`

An IP port integer. It is limited to 0 through 65535, with values below 1024
typically restricted to use by processes running as root. In some cases,
an asterisk (*) character can be used as a placeholder to select
a random high-numbered port.
"""
port_range_BIND: TypeAlias = Annotated[
    str | list[int] | tuple[int, int],
    BindTypeCoreSchema(Validator.validate_portrange),
]
"""
`<portrange>`

A list of a port or a port range. A port range is specified in the form of range
followed by two port s, port_low and port_high, which represents port numbers
from port_low through port_high, inclusive. port_low must not be larger than port_high.
For example, range 1024 65535 represents ports from 1024 through 65535. The asterisk (*)
character is not allowed as a valid port or as a port range boundary.
"""
size_BIND: TypeAlias = Annotated[
    str | int,
    BindTypeCoreSchema(Validator.validate_size),
]
"""
`<size>`

A 64-bit unsigned integer. Integers may take values 0 <= value <= 18446744073709551615,
though certain parameters (such as max-journal-size) may use a more limited range within
these extremes. In most cases, setting a value to 0 does not literally mean zero; it means
"undefined" or "as big as possible," depending on the context. See the explanations
of particular parameters that use size for details on how they interpret its use.
Numeric values can optionally be followed by a scaling factor: K or k for kilobytes,
M or m for megabytes, and G or g for gigabytes, which scale by 1024, 1024*1024,
and 1024*1024*1024 respectively.

Some statements also accept the keywords unlimited or default: unlimited generally
means "as big as possible," and is usually the best way to safely set a very large number.
default uses the limit that was in force when the server was started.
"""
sizeval_BIND: TypeAlias = Annotated[
    str | int,
    BindTypeCoreSchema(Validator.validate_sizeval),
]
"""
`<sizeval>`

A 64-bit unsigned integer. Integers may take values 0 <= value <= 18446744073709551615,
though certain parameters (such as max-journal-size) may use a more limited range within
these extremes. In most cases, setting a value to 0 does not literally mean zero; it means
"undefined" or "as big as possible," depending on the context. See the explanations
of particular parameters that use size for details on how they interpret its use.
Numeric values can optionally be followed by a scaling factor: K or k for kilobytes,
M or m for megabytes, and G or g for gigabytes, which scale by 1024, 1024*1024,
and 1024*1024*1024 respectively.

Some statements also accept the keywords unlimited or default: unlimited generally
means "as big as possible," and is usually the best way to safely set a very large number.
default uses the limit that was in force when the server was started.
"""
acl_name_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_acl_name),
]
"""
`<acl_name>`

The name of an address_match_list as defined by the acl statement.
"""
address_match_element_BIND: TypeAlias = Annotated[
    str,
    BindTypeCoreSchema(Validator.validate_address_match_element),
]
"""
`<address_match_list>`

An element of `[ ! ] ( <ip_address> | <netprefix> | key <server_key> | <acl_name>`
`| { address_match_list } )`
"""
address_match_list_BIND: TypeAlias = Annotated[
    list[Any],
    BindTypeCoreSchema(Validator.validate_address_match_list),
]
"""
`<address_match_element>`

Address match lists are primarily used to determine access control for various
server operations. They are also used in the listen-on and sortlist statements.
The elements which constitute an address match list can be any of the following:
- ip_address: an IP address (IPv4 or IPv6);
- netprefix: an IP prefix (in / notation);
- server_key: a key ID, as defined by the key statement;
- acl_name: the name of an address match list defined with the acl statement;
- a nested address match list enclosed in braces.
"""
