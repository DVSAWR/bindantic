from __future__ import annotations

__author__ = "Gruzdev Daniil"
__email__ = "gruzdev.daniil@gmail.com"
__title__ = "bindantic"
__description__ = "Pydantic-based BIND9 configuration management library"
__version__ = "0.9.0"
__url__ = "https://github.com/DVSAWR/bindantic"
__license__ = "MIT"
__copyright__ = f"Copyright (C) 2026 {__author__}"

# NOTE: BASSE TYPES AND MODELS
from ._base_model import BindBaseModel
from ._base_types import (
    acl_name_BIND,
    address_match_element_BIND,
    address_match_list_BIND,
    boolean_BIND,
    dns_name_BIND,
    domain_name_BIND,
    duration_BIND,
    fixed_point_BIND,
    integer_BIND,
    ip_address_BIND,
    ip_v4_address_BIND,
    ip_v6_address_BIND,
    net_prefix_BIND,
    percentage_BIND,
    port_BIND,
    port_range_BIND,
    quoted_string_BIND,
    server_key_BIND,
    size_BIND,
    sizeval_BIND,
    string_BIND,
    tls_id_BIND,
)

# NOTE: ACL BLOCKS
from .acl_block import AclBlock

# NOTE: CONTROLS BLOCKS
from .controls_block import ControlsBlock, InetControl

# NOTE: DNSSEC POLICIES BLOCKS
from .dnssec_policy_block import (
    DnssecAlgorithmEnum,  # NOTE: Enum
    DnssecDigestTypeEnum,  # NOTE: Enum
    DnssecKeyEntry,
    DnssecPolicyBlock,
    KeyRoleEnum,  # NOTE: Enum
    KeyStorageEnum,  # NOTE: Enum
    Nsec3ParamBlock,
)

# NOTE: HTTP BLOCKS (DNS-over-HTTPS)
from .http_block import HttpBlock

# NOTE: KEY BLOCKS
from .key_block import KeyBlock, KeyStoreBlock

# NOTE: LOGGING BLOCKS
from .logging_block import (
    FileSuffixEnum,  # NOTE: Enum
    LogCategory,
    LogCategoryEnum,  # NOTE: Enum
    LogChannel,
    LoggingBlock,
    LogSeverityEnum,  # NOTE: Enum
    SyslogFacilityEnum,  # NOTE: Enum
    TimeFormatEnum,  # NOTE: Enum
)

# NOTE: MAIN NAMED CONFIG
from .named_config import GeneratedFile, NamedConfig

# NOTE: OPTIONS BLOCKS
from .options_block import (
    AlsoNotifyBlock,
    CatalogZoneBlock,
    Dns64Block,
    ForwardersBlock,
    OptionsBlock,
    RateLimitBlock,
    ResponsePolicyBlock,
    ResponsePolicyZone,
    RrsetOrderRule,
    ServerSpecifier,
)

# NOTE: REMOTE SERVERS BLOCKS
from .remote_servers_block import RemoteServerEntry, RemoteServersBlock

# NOTE: SERVER BLOCKS
from .server_block import ServerBlock

# NOTE: STATISTICS CHANNELS BLOCKS
from .statistics_channels_block import InetChannel, StatisticsChannelsBlock

# NOTE: TLS BLOCKS
from .tls_block import TlsBlock

# NOTE: TRUST ANCHORS BLOCKS
from .trust_anchors_block import (
    AnchorTypeEnum,  # NOTE: Enum
    BaseTrustAnchor,
    DSTrustAnchor,
    KeyTrustAnchor,
    TrustAnchorEntry,
    TrustAnchorsBlock,
)

# NOTE: VIEW BLOCKS
from .view_block import ViewBlock

# NOTE: ZONE BLOCKS
from .zone_block import (
    UpdatePolicyBlock,
    UpdatePolicyRule,
    UpdatePolicyRuleTypeEnum,  # NOTE: Enum
    ZoneBlock,
    ZoneClassEnum,  # NOTE: Enum
    ZoneTypeEnum,  # NOTE: Enum
)

# NOTE: RESOURCE RECORDS (RR) BLOCKS
from .zone_block_resource_records import (
    AAAARecord,
    ARecord,
    CAARecord,
    CAATagEnum,  # NOTE: Enum
    CERTRecord,
    CNAMERecord,
    DNAMERecord,
    DNSKEYRecord,
    DNSSECAlgorithmEnum,  # NOTE: Enum
    DSRecord,
    HINFORecord,
    LOCRecord,
    MXRecord,
    NAPTRRecord,
    NSECRecord,
    NSRecord,
    PTRRecord,
    ResourceRecord,
    ResourceRecordType,
    RPRecord,
    RRClassEnum,  # NOTE: Enum
    RRSIGRecord,
    RRTypeEnum,  # NOTE: Enum
    SOARecord,
    SPFRecord,
    SRVRecord,
    SSHFPAlgorithmEnum,  # NOTE: Enum
    SSHFPHashTypeEnum,  # NOTE: Enum
    SSHFPRecord,
    TLSACertUsageEnum,  # NOTE: Enum
    TLSAMatchingTypeEnum,  # NOTE: Enum
    TLSARecord,
    TLSASelectorEnum,  # NOTE: Enum
    TXTRecord,
    sort_resource_records,  # NOTE: func
)

__all__ = [
    "AAAARecord",
    "ARecord",
    "AclBlock",
    "AlsoNotifyBlock",
    "AnchorTypeEnum",
    "BaseTrustAnchor",
    "BindBaseModel",
    "CAARecord",
    "CAATagEnum",
    "CERTRecord",
    "CNAMERecord",
    "CatalogZoneBlock",
    "ControlsBlock",
    "DNAMERecord",
    "DNSKEYRecord",
    "DNSSECAlgorithmEnum",
    "DSRecord",
    "DSTrustAnchor",
    "Dns64Block",
    "DnssecAlgorithmEnum",
    "DnssecDigestTypeEnum",
    "DnssecKeyEntry",
    "DnssecPolicyBlock",
    "FileSuffixEnum",
    "ForwardersBlock",
    "GeneratedFile",
    "HINFORecord",
    "HttpBlock",
    "InetChannel",
    "InetControl",
    "KeyBlock",
    "KeyRoleEnum",
    "KeyStorageEnum",
    "KeyStoreBlock",
    "KeyTrustAnchor",
    "LOCRecord",
    "LogCategory",
    "LogCategoryEnum",
    "LogChannel",
    "LogSeverityEnum",
    "LoggingBlock",
    "MXRecord",
    "NAPTRRecord",
    "NSECRecord",
    "NSRecord",
    "NamedConfig",
    "Nsec3ParamBlock",
    "OptionsBlock",
    "PTRRecord",
    "RPRecord",
    "RRClassEnum",
    "RRSIGRecord",
    "RRTypeEnum",
    "RateLimitBlock",
    "RemoteServerEntry",
    "RemoteServersBlock",
    "ResourceRecord",
    "ResourceRecordType",
    "ResponsePolicyBlock",
    "ResponsePolicyZone",
    "RrsetOrderRule",
    "SOARecord",
    "SPFRecord",
    "SRVRecord",
    "SSHFPAlgorithmEnum",
    "SSHFPHashTypeEnum",
    "SSHFPRecord",
    "ServerBlock",
    "ServerSpecifier",
    "StatisticsChannelsBlock",
    "SyslogFacilityEnum",
    "TLSACertUsageEnum",
    "TLSAMatchingTypeEnum",
    "TLSARecord",
    "TLSASelectorEnum",
    "TXTRecord",
    "TimeFormatEnum",
    "TlsBlock",
    "TrustAnchorEntry",
    "TrustAnchorsBlock",
    "UpdatePolicyBlock",
    "UpdatePolicyRule",
    "UpdatePolicyRuleTypeEnum",
    "ViewBlock",
    "ZoneBlock",
    "ZoneClassEnum",
    "ZoneTypeEnum",
    "acl_name_BIND",
    "address_match_element_BIND",
    "address_match_list_BIND",
    "boolean_BIND",
    "dns_name_BIND",
    "domain_name_BIND",
    "duration_BIND",
    "fixed_point_BIND",
    "integer_BIND",
    "ip_address_BIND",
    "ip_v4_address_BIND",
    "ip_v6_address_BIND",
    "net_prefix_BIND",
    "percentage_BIND",
    "port_BIND",
    "port_range_BIND",
    "quoted_string_BIND",
    "server_key_BIND",
    "size_BIND",
    "sizeval_BIND",
    "sort_resource_records",
    "string_BIND",
    "tls_id_BIND",
]
