from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar, Final, TypeAlias

from pydantic import Field, model_validator

from ._base_model import BindBaseModel
from ._base_types import (
    dns_name_BIND,
    domain_name_BIND,
    duration_BIND,
    integer_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    port_BIND,
    quoted_string_BIND,
    string_BIND,
)


class RRClassEnum(str, Enum):
    IN = "IN"
    CH = "CH"
    HS = "HS"


class RRTypeEnum(str, Enum):
    # NOTE: Basic RR
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    PTR = "PTR"
    SOA = "SOA"
    TXT = "TXT"
    SPF = "SPF"
    SRV = "SRV"
    DNAME = "DNAME"
    # NOTE: DNSSEC RR
    DS = "DS"
    DNSKEY = "DNSKEY"
    RRSIG = "RRSIG"
    NSEC = "NSEC"
    # NOTE: Security RR
    SSHFP = "SSHFP"
    TLSA = "TLSA"
    CERT = "CERT"
    CAA = "CAA"
    # NOTE: Special RR
    LOC = "LOC"
    RP = "RP"
    HINFO = "HINFO"
    NAPTR = "NAPTR"


class DNSSECAlgorithmEnum(int, Enum):
    """DNSSEC algorithms as defined in RFC 4034."""

    RSAMD5 = 1
    DH = 2
    DSA = 3
    RSASHA1 = 5
    DSANSEC3SHA1 = 6
    RSASHA1NSEC3SHA1 = 7
    RSASHA256 = 8
    RSASHA512 = 10
    ECCGOST = 12
    ECDSAP256SHA256 = 13
    ECDSAP384SHA384 = 14
    ED25519 = 15
    ED448 = 16


class SSHFPAlgorithmEnum(int, Enum):
    """SSHFP algorithm types."""

    RSA = 1
    DSA = 2
    ECDSA = 3
    ED25519 = 4


class SSHFPHashTypeEnum(int, Enum):
    """SSHFP hash types."""

    SHA1 = 1
    SHA256 = 2


class TLSACertUsageEnum(int, Enum):
    """TLSA certificate usage values."""

    PKIX_TA = 0
    PKIX_EE = 1
    DANE_TA = 2
    DANE_EE = 3


class TLSASelectorEnum(int, Enum):
    """TLSA selector values."""

    FULL_CERT = 0
    SUBJECT_PUBLIC_KEY_INFO = 1


class TLSAMatchingTypeEnum(int, Enum):
    """TLSA matching type values."""

    EXACT = 0
    SHA256 = 1
    SHA512 = 2


class CAATagEnum(str, Enum):
    """CAA tag values."""

    ISSUE = "issue"
    ISSUEWILD = "issuewild"
    IODEF = "iodef"
    CONTACT = "contact"


class ResourceRecord(BindBaseModel):
    """Base class for all RR(Resource Records)."""

    _rdata_exclude_fields: ClassVar[set[str]] = {
        "name",
        "ttl",
        "rr_class",
        "rr_type",
        "comment",
        "comparison_attr",
        "origin",
    }

    _multiline_records: ClassVar[set[RRTypeEnum]] = {RRTypeEnum.SOA}

    name: dns_name_BIND | None = Field(
        default=None, description="DNS name (optional, inherits from previous RR)"
    )
    ttl: duration_BIND | None = Field(
        default=None, description="Time to live in seconds (optional)"
    )
    rr_class: RRClassEnum | None = Field(default=RRClassEnum.IN, description="Record class")
    rr_type: RRTypeEnum = Field(..., description="Record type")

    def _get_rdata_fields(self) -> list[tuple[str, Any]]:
        rdata_fields = []

        for field_name, field_info in self.__class__.model_fields.items():
            if field_name in self._rdata_exclude_fields:
                continue

            value = getattr(self, field_name, None)
            if value is None and not field_info.is_required():
                continue

            rdata_fields.append((field_name, value))

        return rdata_fields

    def _format_rdata_value(self, value: Any) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        if isinstance(value, list):
            return " ".join(self._format_rdata_item(item) for item in value)
        if isinstance(value, bool):
            return str(value).lower()
        return str(value)

    def _format_rdata_item(self, item: Any) -> str:
        if isinstance(item, Enum):
            return str(item.value)
        return str(item)

    def _format_rr_header(self) -> str:
        name = self.name or "@"
        ttl = str(self.ttl) if self.ttl is not None else ""
        rr_class = self.rr_class.value if self.rr_class else ""

        return f"{name:<40}{ttl:<9}{rr_class:<5}{self.rr_type.value:<10}"

    def _add_comment(self, lines: list[str], indent_level: int) -> None:
        if self.comment:
            comment_line = self.comment.replace("\n", " ")
            lines[-1] = f"{lines[-1]} ; {comment_line}"

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        if self.rr_type in self._multiline_records:
            return self._format_special_record(indent_level)

        indent = self._indent(indent_level)
        header = self._format_rr_header()
        rdata_fields = self._get_rdata_fields()

        rdata_parts = []
        for _, value in rdata_fields:
            formatted = self._format_rdata_value(value)
            rdata_parts.append(formatted)

        rdata_string = " ".join(rdata_parts)
        lines = [f"{indent}{header} {rdata_string}"]
        self._add_comment(lines, indent_level)

        return "\n".join(lines)

    def _format_special_record(self, indent_level: int) -> str:
        """Convert multiline RR to BIND syntax from _multiline_records(SOA)."""
        raise NotImplementedError(
            f"Record type {self.rr_type} requires special formatting. "
            f"Override '_format_special_record' method."
        )

    @model_validator(mode="after")
    def validate_rr_class(self) -> ResourceRecord:
        if self.rr_class is None:
            self.rr_class = RRClassEnum.IN
        return self


class ARecord(ResourceRecord):
    """
    A record - maps a hostname to an IPv4 address.

    Grammar (Reference: RFC 1035 Section 3.4.1):
    ```
    [<NAME>] [<TTL>] [<CLASS>] A <ADDRESS>
    ```
    """

    address: ip_v4_address_BIND = Field(..., description="IPv4 address")
    rr_type: RRTypeEnum = RRTypeEnum.A

    @property
    def comparison_attr(self) -> str:
        return f"A:{self.name or '@'}:{self.address}"


class AAAARecord(ResourceRecord):
    """
    AAAA record - maps a hostname to an IPv6 address.

    Grammar (Reference: RFC 3596 Section 2.2):
    ```
    [<NAME>] [<TTL>] [<CLASS>] AAAA <ADDRESS>
    ```
    """

    address: ip_v6_address_BIND = Field(..., description="IPv6 address")
    rr_type: RRTypeEnum = RRTypeEnum.AAAA

    @property
    def comparison_attr(self) -> str:
        return f"AAAA:{self.name or '@'}:{self.address}"


class CNAMERecord(ResourceRecord):
    """
    CNAME record - alias for another domain name.

    Grammar (Reference: RFC 1035 Section 3.3.1):
    ```
    [<NAME>] [<TTL>] [<CLASS>] CNAME <CANONICAL_NAME>
    ```
    """

    canonical_name: domain_name_BIND = Field(
        ..., description="Canonical domain name (the real name)"
    )
    rr_type: RRTypeEnum = RRTypeEnum.CNAME

    @property
    def comparison_attr(self) -> str:
        return f"CNAME:{self.name or '@'}:{self.canonical_name}"


class DNAMERecord(ResourceRecord):
    """
    DNAME record - delegation name (creates a subtree delegation).

    Grammar (Reference: RFC 6672 Section 2):
    ```
    [<NAME>] [<TTL>] [<CLASS>] DNAME <TARGET>
    ```
    """

    target: domain_name_BIND = Field(..., description="Target domain name for delegation")
    rr_type: RRTypeEnum = RRTypeEnum.DNAME

    @property
    def comparison_attr(self) -> str:
        return f"DNAME:{self.name or '@'}:{self.target}"


class MXRecord(ResourceRecord):
    """
    MX record - mail exchange server with priority.

    Grammar (Reference: RFC 1035 Section 3.3.9):
    ```
    [<NAME>] [<TTL>] [<CLASS>] MX <PREFERENCE> <EXCHANGE>
    ```
    """

    preference: integer_BIND = Field(
        ..., ge=0, le=65535, description="Priority (lower value = higher priority)"
    )
    exchange: domain_name_BIND = Field(..., description="Hostname of mail server")
    rr_type: RRTypeEnum = RRTypeEnum.MX

    @property
    def comparison_attr(self) -> str:
        return f"MX:{self.name or '@'}:{self.preference}:{self.exchange}"


class NSRecord(ResourceRecord):
    """
    NS record - authoritative name server for a domain.

    Grammar (Reference: RFC 1035 Section 3.3.11):
    ```
    [<NAME>] [<TTL>] [<CLASS>] NS <NSDNAME>
    ```
    """

    nsdname: domain_name_BIND = Field(..., description="Hostname of authoritative name server")
    rr_type: RRTypeEnum = RRTypeEnum.NS

    @property
    def comparison_attr(self) -> str:
        return f"NS:{self.name or '@'}:{self.nsdname}"


class PTRRecord(ResourceRecord):
    """
    PTR record - pointer for reverse DNS lookups.

    Grammar (Reference: RFC 1035 Section 3.3.12):
    ```
    [<NAME>] [<TTL>] [<CLASS>] PTR <DOMAIN_NAME>
    ```
    """

    domain_name: domain_name_BIND = Field(..., description="Canonical domain name")
    rr_type: RRTypeEnum = RRTypeEnum.PTR

    @property
    def comparison_attr(self) -> str:
        return f"PTR:{self.name or '@'}:{self.domain_name}"


class SOARecord(ResourceRecord):
    """
    SOA record - defines authoritative information for the zone.

    Grammar (Reference: RFC 1035 Section 3.3.13):
    ```
    [<NAME>] [<TTL>] [<CLASS>] SOA <MNAME> <RNAME> (
        <SERIAL> <REFRESH> <RETRY> <EXPIRE> <MINIMUM>
    )
    """

    mname: domain_name_BIND = Field(..., description="Primary master name server")
    rname: domain_name_BIND = Field(
        ..., description="Email address of responsible person (@ replaced by .)"
    )
    serial: integer_BIND = Field(..., description="Zone serial number (32-bit unsigned)")
    refresh: duration_BIND = Field(..., description="Refresh interval in seconds")
    retry: duration_BIND = Field(..., description="Retry interval in seconds")
    expire: duration_BIND = Field(..., description="Expire time in seconds")
    minimum: duration_BIND = Field(..., description="Minimum TTL in seconds (negative cache)")
    rr_type: RRTypeEnum = RRTypeEnum.SOA

    # NOTE: $GLOBAL_TYPE
    ttl: duration_BIND | None = Field(
        default=None, description="Global $TTL for the zone (optional)"
    )
    origin: domain_name_BIND | None = Field(default=None, description="Global $ORIGIN domain name")

    @property
    def comparison_attr(self) -> str:
        return f"SOA:{self.name or '@'}:{self.mname}"

    def model_bind_syntax(self, indent_level: int = 0) -> str:
        indent = self._indent(indent_level)
        lines = []

        if self.comment:
            comment_lines = self.comment.split("\n")
            for line in comment_lines:
                lines.append(f"{indent}; {line}")

        if self.ttl is not None:
            lines.append(f"{indent}$TTL {self.ttl}")
        if self.origin is not None:
            lines.append(f"{indent}$ORIGIN {self.origin}")

        header_parts = []
        if self.name is not None:
            header_parts.append(f"{self.name:<48}")
        else:
            header_parts.append(f"{'@':<48}")

        if self.rr_class is not None:
            header_parts.append(f"{self.rr_class.value:<4}")
        else:
            header_parts.append(f"{RRClassEnum.IN.value:<4}")

        header_parts.append(self.rr_type.value)
        header_parts.append(self.mname)
        header_parts.append(self.rname)
        header_parts.append("(")

        lines.append(f"{indent}{' '.join(header_parts)}")

        inner_indent = self._indent(indent_level)
        lines.extend(
            [
                f"{inner_indent}{'':<65}{self.serial:<10} ; Serial number (YYYYMMDDNN)",
                f"{inner_indent}{'':<65}{self.refresh:<10} ; Refresh time",
                f"{inner_indent}{'':<65}{self.retry:<10} ; Retry time",
                f"{inner_indent}{'':<65}{self.expire:<10} ; Expire time",
                f"{inner_indent}{'':<65}{self.minimum:<10} ; Minimum TTL",
                f"{inner_indent}{'':<54})",
            ]
        )

        return "\n".join(lines)


class TXTRecord(ResourceRecord):
    """
    TXT record - text strings associated with a domain.

    Grammar (Reference: RFC 1035 Section 3.3.14):
    ```
    [<NAME>] [<TTL>] [<CLASS>] TXT "<TEXT_DATA>"
    ```
    """

    text_data: list[quoted_string_BIND] = Field(
        ..., description="List of text strings (each max 255 chars)"
    )
    rr_type: RRTypeEnum = RRTypeEnum.TXT

    @model_validator(mode="after")
    def validate_text_length(self) -> TXTRecord:
        """Validate each text string doesn't exceed 255 characters."""
        for text in self.text_data:
            content = text.strip('"')
            if len(content) > 255:
                raise ValueError(f"TXT string too long: {len(content)} > 255 chars")
        return self

    @property
    def comparison_attr(self) -> str:
        return f"TXT:{self.name or '@'}:{self.text_data[0][:20]}"


class SPFRecord(ResourceRecord):
    """
    SPF record - Sender Policy Framework (syntactic equivalent to TXT).

    Grammar (Reference: RFC 4408):
    ```
    [<NAME>] [<TTL>] [<CLASS>] SPF "<SPF_DATA>"
    ```
    """

    spf_data: list[quoted_string_BIND] = Field(..., description="SPF policy text")
    rr_type: RRTypeEnum = RRTypeEnum.SPF

    @property
    def comparison_attr(self) -> str:
        return f"SPF:{self.name or '@'}:{self.spf_data[0][:20]}"


class SRVRecord(ResourceRecord):
    """
    SRV record - service location record.

    Grammar (Reference: RFC 2782):
    ```
    [<NAME>] [<TTL>] [<CLASS>] SRV <PRIORITY> <WEIGHT> <PORT> <TARGET>
    ```
    """

    priority: integer_BIND = Field(
        ..., ge=0, le=65535, description="Priority (lower value = higher priority)"
    )
    weight: integer_BIND = Field(..., ge=0, le=65535, description="Weight for load balancing")
    port: port_BIND = Field(..., description="Service port number")
    target: dns_name_BIND = Field(..., description="Target hostname")
    rr_type: RRTypeEnum = RRTypeEnum.SRV

    @property
    def comparison_attr(self) -> str:
        return f"SRV:{self.name or '@'}:{self.priority}:{self.target}"


class DSRecord(ResourceRecord):
    """
    DS record - delegation signer (DNSSEC).

    Grammar (Reference: RFC 4034):
    ```
    [<NAME>] [<TTL>] [<CLASS>] DS <KEY_TAG> <ALGORITHM> <DIGEST_TYPE> <DIGEST>
    ```
    """

    key_tag: integer_BIND = Field(
        ...,
        ge=0,
        le=65535,
        description="Key tag value",
    )
    algorithm: DNSSECAlgorithmEnum = Field(..., description="DNSSEC algorithm used")
    digest_type: integer_BIND = Field(
        ..., ge=0, le=255, description="Digest type (1=SHA-1, 2=SHA-256)"
    )
    digest: string_BIND = Field(..., description="Hexadecimal digest value")
    rr_type: RRTypeEnum = RRTypeEnum.DS

    @property
    def comparison_attr(self) -> str:
        return f"DS:{self.name or '@'}:{self.key_tag}"


class DNSKEYRecord(ResourceRecord):
    """
    DNSKEY record - DNS public key (DNSSEC).

    Grammar (Reference: RFC 4034):
    ```
    [<NAME>] [<TTL>] [<CLASS>] DNSKEY <FLAGS> <PROTOCOL> <ALGORITHM> <PUBLIC_KEY>
    ```
    """

    flags: integer_BIND = Field(
        ..., ge=0, le=65535, description="Flags (256=Zone Key, 257=Secure Entry Point)"
    )
    protocol: integer_BIND = Field(default=3, description="Protocol (always 3 for DNSSEC)")
    algorithm: DNSSECAlgorithmEnum = Field(..., description="DNSSEC algorithm used")
    public_key: string_BIND = Field(..., description="Base64 encoded public key")
    rr_type: RRTypeEnum = RRTypeEnum.DNSKEY

    @property
    def comparison_attr(self) -> str:
        return f"DNSKEY:{self.name or '@'}:{self.flags}"


class RRSIGRecord(ResourceRecord):
    """
    RRSIG record - digital signature for RRset (DNSSEC).

    Grammar (Reference: RFC 4034):
    ```
    [<NAME>] [<TTL>] [<CLASS>] RRSIG <TYPE_COVERED> <ALGORITHM> <LABELS>
        <ORIGINAL_TTL> <SIGNATURE_EXPIRATION> <SIGNATURE_INCEPTION>
        <KEY_TAG> <SIGNER_NAME> <SIGNATURE>
    ```
    """

    type_covered: string_BIND = Field(..., description="RR type covered by signature")
    algorithm: DNSSECAlgorithmEnum = Field(..., description="DNSSEC algorithm used")
    labels: integer_BIND = Field(..., description="Number of labels in original name")
    original_ttl: duration_BIND = Field(..., description="Original TTL of RRset")
    signature_expiration: integer_BIND | string_BIND = Field(
        ..., description="Signature expiration time (Unix timestamp)"
    )
    signature_inception: integer_BIND | string_BIND = Field(
        ..., description="Signature inception time (Unix timestamp)"
    )
    key_tag: integer_BIND = Field(..., description="Key tag value")
    signer_name: domain_name_BIND = Field(..., description="Name of signing key")
    signature: string_BIND = Field(..., description="Base64 encoded signature")
    rr_type: RRTypeEnum = RRTypeEnum.RRSIG

    @property
    def comparison_attr(self) -> str:
        return f"RRSIG:{self.name or '@'}:{self.type_covered}"


class NSECRecord(ResourceRecord):
    """
    NSEC record - next secure record (DNSSEC).

    Grammar (Reference: RFC 4034):
    ```
    [<NAME>] [<TTL>] [<CLASS>] NSEC <NEXT_DOMAIN_NAME> <TYPE_BIT_MAPS>
    ```
    """

    next_domain_name: domain_name_BIND = Field(..., description="Next domain name in zone")
    type_bit_maps: list[string_BIND] = Field(..., description="Type bit maps")
    rr_type: RRTypeEnum = RRTypeEnum.NSEC

    @property
    def comparison_attr(self) -> str:
        return f"NSEC:{self.name or '@'}:{self.next_domain_name}"


class SSHFPRecord(ResourceRecord):
    """
    SSHFP record - SSH public key fingerprint.

    Grammar (Reference: RFC 4255):
    ```
    [<NAME>] [<TTL>] [<CLASS>] SSHFP <ALGORITHM> <HASH_TYPE> <FINGERPRINT>
    ```
    """

    algorithm: SSHFPAlgorithmEnum = Field(..., description="SSH key algorithm")
    hash_type: SSHFPHashTypeEnum = Field(..., description="Hash algorithm used")
    fingerprint: string_BIND = Field(..., description="Hexadecimal fingerprint")
    rr_type: RRTypeEnum = RRTypeEnum.SSHFP

    @property
    def comparison_attr(self) -> str:
        return f"SSHFP:{self.name or '@'}:{self.algorithm.name}"


class TLSARecord(ResourceRecord):
    """
    TLSA record - TLS certificate association (DANE).

    Grammar (Reference: RFC 6698):
    ```
    [<NAME>] [<TTL>] [<CLASS>] TLSA <CERT_USAGE> <SELECTOR> <MATCHING_TYPE> <CERT_DATA>
    ```
    """

    cert_usage: TLSACertUsageEnum = Field(..., description="Certificate usage")
    selector: TLSASelectorEnum = Field(..., description="Part of certificate selected")
    matching_type: TLSAMatchingTypeEnum = Field(..., description="How certificate is presented")
    cert_data: string_BIND = Field(..., description="Certificate association data")
    rr_type: RRTypeEnum = RRTypeEnum.TLSA

    @property
    def comparison_attr(self) -> str:
        return f"TLSA:{self.name or '@'}:{self.cert_usage.name}"


class CAARecord(ResourceRecord):
    """
    CAA record - Certification Authority Authorization.

    Grammar (Reference: RFC 6844):
    ```
    [<NAME>] [<TTL>] [<CLASS>] CAA <FLAGS> <TAG> "<VALUE>"
    ```
    """

    flags: integer_BIND = Field(
        default=0, ge=0, le=255, description="Flags (0-255, usually 0 or 128 for critical)"
    )
    tag: CAATagEnum = Field(..., description="CAA property tag")
    value: quoted_string_BIND = Field(..., description="Property value")
    rr_type: RRTypeEnum = RRTypeEnum.CAA

    @property
    def comparison_attr(self) -> str:
        return f"CAA:{self.name or '@'}:{self.tag.value}"


class CERTRecord(ResourceRecord):
    """
    CERT record - certificate storage.

    Grammar (Reference: RFC 4398):
    ```
    [<NAME>] [<TTL>] [<CLASS>] CERT <CERT_TYPE> <KEY_TAG> <ALGORITHM> <CERTIFICATE>
    ```
    """

    cert_type: integer_BIND = Field(..., description="Certificate type")
    key_tag: integer_BIND = Field(..., description="Key tag")
    algorithm: integer_BIND = Field(..., description="Algorithm")
    certificate: string_BIND = Field(..., description="Certificate data")
    rr_type: RRTypeEnum = RRTypeEnum.CERT

    @property
    def comparison_attr(self) -> str:
        return f"CERT:{self.name or '@'}:{self.cert_type}"


class LOCRecord(ResourceRecord):
    """
    LOC record - geographical location.

    Grammar (Reference: RFC 1876):
    ```
    [<NAME>] [<TTL>] [<CLASS>] LOC <LATITUDE> <LONGITUDE> <ALTITUDE>
        <SIZE> <HPREC> <VPREC>
    ```
    """

    latitude: string_BIND = Field(..., description="Latitude (e.g., 51 30 12.123 N)")
    longitude: string_BIND = Field(..., description="Longitude (e.g., 0 7 39.456 W)")
    altitude: integer_BIND | string_BIND = Field(..., description="Altitude in meters")
    size: float | string_BIND = Field(..., description="Diameter of sphere in meters")
    hprecision: float | string_BIND = Field(..., description="Horizontal precision in meters")
    vprecision: float | string_BIND = Field(..., description="Vertical precision in meters")
    rr_type: RRTypeEnum = RRTypeEnum.LOC

    @property
    def comparison_attr(self) -> str:
        return f"LOC:{self.name or '@'}:{self.latitude[:10]}"


class NAPTRRecord(ResourceRecord):
    """
    NAPTR record - naming authority pointer.

    Grammar (Reference: RFC 3403):
    ```
    [<NAME>] [<TTL>] [<CLASS>] NAPTR <ORDER> <PREFERENCE> <FLAGS>
        <SERVICES> "<REGEXP>" <REPLACEMENT>
    ```
    """

    order: integer_BIND = Field(..., description="Order (lower processed first)")
    preference: integer_BIND = Field(..., description="Preference within same order")
    flags: string_BIND = Field(..., description="Flags (S, A, U, P)")
    services: string_BIND = Field(..., description="Service parameters")
    regexp: quoted_string_BIND = Field(..., description="Regular expression")
    replacement: dns_name_BIND = Field(..., description="Replacement dns name")
    rr_type: RRTypeEnum = RRTypeEnum.NAPTR

    @property
    def comparison_attr(self) -> str:
        return f"NAPTR:{self.name or '@'}:{self.order}:{self.services}"


class HINFORecord(ResourceRecord):
    """
    HINFO record - host information.

    Grammar (Reference: RFC 1035 Section 3.3.11):
    ```
    [<NAME>] [<TTL>] [<CLASS>] HINFO "<CPU>" "<OS>"
    ```
    """

    cpu: string_BIND = Field(
        ...,
        description="CPU type",
    )
    os: string_BIND = Field(
        ...,
        description="Operating system",
    )
    rr_type: RRTypeEnum = RRTypeEnum.HINFO

    @property
    def comparison_attr(self) -> str:
        return f"HINFO:{self.name or '@'}:{self.cpu}"


class RPRecord(ResourceRecord):
    """
    RP record - responsible person.

    Grammar (Reference: RFC 1183):
    ```
    [<NAME>] [<TTL>] [<CLASS>] RP <MBOX_DNAME> <TXT_DNAME>
    ```
    """

    mbox_dname: domain_name_BIND = Field(..., description="Mailbox domain name")
    txt_dname: domain_name_BIND = Field(..., description="TXT record domain name")
    rr_type: RRTypeEnum = RRTypeEnum.RP

    @property
    def comparison_attr(self) -> str:
        return f"RP:{self.name or '@'}:{self.mbox_dname}"


# NOTE: TYPE ALIASES AND REGISTRY
ResourceRecordType: TypeAlias = (
    ARecord
    | AAAARecord
    | CNAMERecord
    | DNAMERecord
    | MXRecord
    | NSRecord
    | PTRRecord
    | SOARecord
    | TXTRecord
    | SPFRecord
    | SRVRecord
    | DSRecord
    | DNSKEYRecord
    | RRSIGRecord
    | NSECRecord
    | SSHFPRecord
    | TLSARecord
    | CAARecord
    | CERTRecord
    | LOCRecord
    | NAPTRRecord
    | HINFORecord
    | RPRecord
)


@dataclass(frozen=True)
class RRTypeInfo:
    record_class: type[ResourceRecord]
    sort_priority: int


RR_TYPE_INFO: Final[dict[RRTypeEnum, RRTypeInfo]] = {
    RRTypeEnum.SOA: RRTypeInfo(SOARecord, 0),
    RRTypeEnum.NS: RRTypeInfo(NSRecord, 1),
    RRTypeEnum.MX: RRTypeInfo(MXRecord, 2),
    RRTypeEnum.A: RRTypeInfo(ARecord, 3),
    RRTypeEnum.AAAA: RRTypeInfo(AAAARecord, 4),
    RRTypeEnum.CNAME: RRTypeInfo(CNAMERecord, 5),
    RRTypeEnum.TXT: RRTypeInfo(TXTRecord, 6),
    RRTypeEnum.SPF: RRTypeInfo(SPFRecord, 7),
    RRTypeEnum.SRV: RRTypeInfo(SRVRecord, 8),
    RRTypeEnum.PTR: RRTypeInfo(PTRRecord, 9),
    RRTypeEnum.DNAME: RRTypeInfo(DNAMERecord, 10),
    RRTypeEnum.DNSKEY: RRTypeInfo(DNSKEYRecord, 11),
    RRTypeEnum.DS: RRTypeInfo(DSRecord, 12),
    RRTypeEnum.RRSIG: RRTypeInfo(RRSIGRecord, 13),
    RRTypeEnum.NSEC: RRTypeInfo(NSECRecord, 14),
    RRTypeEnum.SSHFP: RRTypeInfo(SSHFPRecord, 15),
    RRTypeEnum.TLSA: RRTypeInfo(TLSARecord, 17),
    RRTypeEnum.CAA: RRTypeInfo(CAARecord, 18),
    RRTypeEnum.CERT: RRTypeInfo(CERTRecord, 19),
    RRTypeEnum.LOC: RRTypeInfo(LOCRecord, 20),
    RRTypeEnum.NAPTR: RRTypeInfo(NAPTRRecord, 21),
    RRTypeEnum.HINFO: RRTypeInfo(HINFORecord, 22),
    RRTypeEnum.RP: RRTypeInfo(RPRecord, 23),
}


RR_TYPE_REGISTRY: Final[dict[RRTypeEnum, type[ResourceRecord]]] = {
    rr_type: info.record_class for rr_type, info in RR_TYPE_INFO.items()
}

RR_TYPE_PRIORITY: Final[dict[RRTypeEnum, int]] = {
    rr_type: info.sort_priority for rr_type, info in RR_TYPE_INFO.items()
}


def sort_resource_records(records: list[ResourceRecord]) -> list[ResourceRecord]:
    """Sort resource records by priority in BIND."""

    def sort_key(rr: ResourceRecord) -> tuple[int, str]:
        priority = RR_TYPE_PRIORITY.get(rr.rr_type, 100)
        name = rr.name or "@"
        name_key = "" if name == "@" else name
        name_parts = name_key.split(".") if name_key else []
        name_parts_reversed = list(reversed(name_parts))
        return (priority, name_key, *name_parts_reversed, rr.comparison_attr)

    return sorted(records, key=sort_key)
