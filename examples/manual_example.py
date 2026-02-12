from __future__ import annotations

from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network

from bindantic import (
    AAAARecord,
    AclBlock,
    AlsoNotifyBlock,
    AnchorTypeEnum,
    ARecord,
    CAARecord,
    CAATagEnum,
    CatalogZoneBlock,
    CNAMERecord,
    ControlsBlock,
    Dns64Block,
    DNSKEYRecord,
    DNSSECAlgorithmEnum,
    DnssecAlgorithmEnum,
    DnssecDigestTypeEnum,
    DnssecKeyEntry,
    DnssecPolicyBlock,
    DSRecord,
    DSTrustAnchor,
    FileSuffixEnum,
    ForwardersBlock,
    HttpBlock,
    InetChannel,
    InetControl,
    KeyBlock,
    KeyRoleEnum,
    KeyStorageEnum,
    KeyStoreBlock,
    KeyTrustAnchor,
    LogCategory,
    LogCategoryEnum,
    LogChannel,
    LoggingBlock,
    LogSeverityEnum,
    MXRecord,
    NamedConfig,
    Nsec3ParamBlock,
    NSRecord,
    OptionsBlock,
    RateLimitBlock,
    RemoteServerEntry,
    RemoteServersBlock,
    ResponsePolicyBlock,
    ResponsePolicyZone,
    RrsetOrderRule,
    RRSIGRecord,
    ServerBlock,
    ServerSpecifier,
    SOARecord,
    SRVRecord,
    SSHFPAlgorithmEnum,
    SSHFPHashTypeEnum,
    SSHFPRecord,
    StatisticsChannelsBlock,
    SyslogFacilityEnum,
    TimeFormatEnum,
    TLSACertUsageEnum,
    TLSAMatchingTypeEnum,
    TLSARecord,
    TLSASelectorEnum,
    TlsBlock,
    TrustAnchorsBlock,
    TXTRecord,
    UpdatePolicyBlock,
    UpdatePolicyRule,
    UpdatePolicyRuleTypeEnum,
    ViewBlock,
    ZoneBlock,
    ZoneClassEnum,
    ZoneTypeEnum,
)

# NOTE: ACL BLOCK
acl_internal_networks = AclBlock(
    name="internal_networks", addresses=["192.168.1.0/24", "10.0.0.0/8", "2001:db8::/32"]
)
acl_dns_servers = AclBlock.model_validate(
    {"name": "dns_servers", "addresses": ["8.8.8.8", "8.8.4.4", "1.1.1.1"]}
)
acl_trusted_hosts = AclBlock.model_validate_json(
    """{
    "name": "trusted_hosts",
    "addresses": ["192.168.0.1", "192.168.0.2"]
}"""
)
print(acl_internal_networks)
# comment=None name='internal_networks' addresses=['192.168.1.0/24', '10.0.0.0/8', '2001:db8::/32']
print(acl_dns_servers.model_dump())
# {'comment': None, 'name': 'dns_servers', 'addresses': ['8.8.8.8', '8.8.4.4', '1.1.1.1']}
print(acl_trusted_hosts.model_bind_syntax())
# acl trusted_hosts {
#     192.168.0.1;
#     192.168.0.2;
# };

# NOTE: CONTROL BLOCK
inet_control_1 = InetControl(
    ip_address="127.0.0.1",
    port=953,
    allow=["127.0.0.1", "::1", "key mykey"],
    keys=["mykey1", "mykey2"],
    read_only="yes",
)
inet_control_2 = InetControl(
    ip_address=IPv6Address("::1"),
    port="*",
    allow=[IPv4Network("192.168.1.0/24"), "2001:db8::/32"],
    keys=None,
    read_only=False,
)
inet_control_3 = InetControl(ip_address="*", port=1053, allow=["any"], read_only=True)
print(inet_control_1.model_bind_syntax())
# inet 127.0.0.1
#     allow {
#         127.0.0.1;
#         ::1;
#         key mykey;
#     }
#     keys {
#         mykey1;
#         mykey2;
#     }
#     read-only yes
# ;
print(inet_control_2.model_bind_syntax())
# inet ::1 port *
#     allow {
#         192.168.1.0/24;
#         2001:db8::/32;
#     }
#     read-only no
# ;
print(inet_control_3.model_bind_syntax())
# inet * port 1053
#     allow {
#         any;
#     }
#     read-only yes
# ;
print(inet_control_3.model_bind_syntax())

controls_empty = ControlsBlock(controls=[])
controls_single = ControlsBlock(
    controls=[
        InetControl(ip_address="127.0.0.1", allow=["localhost"], keys=["rndc-key"], read_only="no")
    ]
)
controls_multi = ControlsBlock(controls=[inet_control_1, inet_control_2])
print(controls_empty.model_bind_syntax())
# controls { };
print(controls_single.model_bind_syntax())
# controls {
#     inet 127.0.0.1
#         allow {
#             localhost;
#         }
#         keys {
#             rndc-key;
#         }
#         read-only no
#     ;
# };
print(controls_multi.model_bind_syntax())
# controls {
#     inet 127.0.0.1
#         allow {
#             127.0.0.1;
#             ::1;
#             key mykey;
#         }
#         keys {
#             mykey1;
#             mykey2;
#         }
#         read-only yes
#     ;
#     inet ::1 port *
#         allow {
#             192.168.1.0/24;
#             2001:db8::/32;
#         }
#         read-only no
#     ;
# };

# NOTE: DNSSEC POLICY
key_csk = DnssecKeyEntry(
    role=KeyRoleEnum.CSK,
    storage_type=KeyStorageEnum.KEY_DIRECTORY,
    lifetime="P1Y",
    algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
    key_size=2048,
    tag_range=(1000, 2000),
)
key_ksk = DnssecKeyEntry(
    role=KeyRoleEnum.KSK,
    storage_type=KeyStorageEnum.KEY_STORE,
    key_store_name="my-keystore",
    lifetime="90d",
    algorithm="ed25519",
    key_size=256,
)
key_zsk = DnssecKeyEntry(
    role=KeyRoleEnum.ZSK,
    lifetime="unlimited",
    algorithm=14,
)
print(key_csk.model_bind_syntax())
# csk key-directory lifetime 31536000 algorithm ecdsap256sha256 tag-range 1000 2000 2048;
print(key_ksk.model_bind_syntax())
# ksk key-store my-keystore lifetime 7776000 algorithm ed25519 256;
print(key_zsk.model_bind_syntax())
# zsk lifetime unlimited algorithm ecdsap384sha384;

nsec3_full = Nsec3ParamBlock(iterations=10, optout=True, salt_length=8)
nsec3_minimal = Nsec3ParamBlock(optout=1, salt_length=0)
nsec3_iterations = Nsec3ParamBlock(iterations=5)
print(nsec3_full.model_bind_syntax())
# nsec3param iterations 10 optout yes salt-length 8;
print(nsec3_minimal.model_bind_syntax())
# nsec3param optout yes salt-length 0;
print(nsec3_iterations.model_bind_syntax())
# nsec3param iterations 5;

policy_custom = DnssecPolicyBlock(
    name="policy_custom",
    cdnskey=True,
    inline_signing="yes",
    dnskey_ttl="2h",
    max_zone_ttl="1d",
    cds_digest_types=[DnssecDigestTypeEnum.SHA256, DnssecDigestTypeEnum.SHA512],
    keys=[key_zsk],
    nsec3param=nsec3_full,
)
policy_mixed = DnssecPolicyBlock(
    name="policy_mixed",
    manual_mode=0,
    offline_ksk=False,
    parent_propagation_delay=3600,
    publish_safety="PT1H",
    signatures_refresh="5D",
    cds_digest_types=[DnssecDigestTypeEnum.SHA256, DnssecDigestTypeEnum.SHA384],
    keys=[key_zsk],
)
print(policy_custom.model_bind_syntax())
# dnssec-policy policy_custom {
#     cdnskey yes;
#     cds-digest-types {
#         SHA-256;
#         SHA-512;
#     };
#     dnskey-ttl 7200;
#     inline-signing yes;
#     keys {
#         zsk lifetime unlimited algorithm ecdsap384sha384;
#     };
#     max-zone-ttl 86400;
#     nsec3param iterations 10 optout yes salt-length 8;
# };
print(policy_mixed.model_bind_syntax())
# dnssec-policy policy_mixed {
#     cds-digest-types {
#         SHA-256;
#         SHA-384;
#     };
#     keys {
#         zsk lifetime unlimited algorithm ecdsap384sha384;
#     };
#     manual-mode no;
#     offline-ksk no;
#     parent-propagation-delay 3600;
#     publish-safety 3600;
#     signatures-refresh 432000;
# };

# NOTE: HTTP
http_basic = HttpBlock(
    name="doh_server",
    endpoints=["/dns-query", "/resolve"],
    listener_clients=100,
    streams_per_connection=100,
)
http_quoted = HttpBlock(
    name="api_gateway",
    endpoints=['"/api/dns"', '"/v1/query"', '"/secure/resolve"'],
    listener_clients=500,
    streams_per_connection=250,
)
http_simple = HttpBlock(
    name="simple_doh", endpoints=["/dns"], listener_clients=0, streams_per_connection=0
)
print(http_basic.model_bind_syntax())
# http doh_server {
#     endpoints {
#         "/dns-query";
#         "/resolve";
#     };
#     listener-clients 100;
#     streams-per-connection 100;
# };
print(http_quoted.model_bind_syntax())
# http api_gateway {
#     endpoints {
#         "/api/dns";
#         "/secure/resolve";
#         "/v1/query";
#     };
#     listener-clients 500;
#     streams-per-connection 250;
# };
print(http_simple.model_bind_syntax())
# http simple_doh {
#     endpoints {
#         "/dns";
#     };
#     listener-clients 0;
#     streams-per-connection 0;
# };

# NOTE: KEY
rndc_key = KeyBlock(name="rndc-key", algorithm="hmac-sha256", secret="aGVsbG8td29ybGQ=")
tsig_key = KeyBlock(
    name='"tsig-key"', algorithm="hmac-sha1-80", secret='"dGhpcy1pcy1hLXNlY3JldA=="'
)
secure_key = KeyBlock(
    name="secure-key",
    algorithm="hmac-sha512",
    secret="YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGY=",
)
print(rndc_key.model_bind_syntax())
# key "rndc-key" {
#     algorithm hmac-sha256;
#     secret "aGVsbG8td29ybGQ=";
# };
print(tsig_key.model_bind_syntax())
# key "tsig-key" {
#     algorithm hmac-sha1-80;
#     secret "dGhpcy1pcy1hLXNlY3JldA==";
# };
print(secure_key.model_bind_syntax())
# key "secure-key" {
#     algorithm hmac-sha512;
#     secret "YXNkZmFzZGZhc2RmYXNkZmFzZGZhc2RmYXNkZmFzZGY=";
# };

local_keys_store = KeyStoreBlock(name="local-keys", directory="/etc/bind/keys")
hsm_keys_stroe = KeyStoreBlock(
    name="hsm-keys", pkcs11_uri='"pkcs11:token=bind-token;object=key-object"'
)
mixed_keys_store = KeyStoreBlock(
    name="mixed-keys",
    directory="/var/lib/bind/keys",
    pkcs11_uri='"pkcs11:manufacturer=pkcs11-token;id=01"',
)
print(local_keys_store.model_bind_syntax())
# key-store local-keys {
#     directory /etc/bind/keys;
# };
print(hsm_keys_stroe.model_bind_syntax())
# key-store hsm-keys {
#     pkcs11-uri "pkcs11:token=bind-token;object=key-object";
# };
print(mixed_keys_store.model_bind_syntax())
# key-store mixed-keys {
#     directory /var/lib/bind/keys;
#     pkcs11-uri "pkcs11:manufacturer=pkcs11-token;id=01";
# };

# NOTE: LOGGING
channel_file = LogChannel(
    name="logfile",
    file="/var/log/bind/query.log",
    versions=10,
    size="100M",
    suffix=FileSuffixEnum.TIMESTAMP,
    buffered=True,
    print_category=True,
    print_severity=True,
    print_time=TimeFormatEnum.ISO8601,
    severity=LogSeverityEnum.INFO,
)
channel_syslog = LogChannel(
    name="syslog_channel",
    syslog=SyslogFacilityEnum.DAEMON,
    print_category=False,
    print_severity="no",
    print_time="iso8601-utc",
    severity="debug 3",
)
channel_stderr = LogChannel(name="stderr_channel", stderr=True, severity="warning")
channel_null = LogChannel(name="null_channel", null=True)
print(channel_file.model_bind_syntax())
# channel logfile {
#     file "/var/log/bind/query.log" versions 10 size 100M suffix timestamp;
#     buffered yes;
#     print-category yes;
#     print-severity yes;
#     print-time iso8601;
#     severity info;
# };
print(channel_syslog.model_bind_syntax())
# channel syslog_channel {
#     syslog daemon;
#     print-category no;
#     print-severity no;
#     print-time iso8601-utc;
#     severity debug 3;
# };
print(channel_stderr.model_bind_syntax())
# channel stderr_channel {
#     stderr;
#     severity warning;
# };
print(channel_null.model_bind_syntax())
# channel null_channel {
#     null;
# };

category_queries = LogCategory(
    name=LogCategoryEnum.QUERIES, channels=[channel_file.name, "syslog_channel"]
)
category_security = LogCategory(
    name=LogCategoryEnum.SECURITY,
    channels=["syslog_channel", "stderr_channel"],
)
category_default = LogCategory(
    name=LogCategoryEnum.DEFAULT, channels=["default_syslog", "logfile"]
)
print(category_queries.model_bind_syntax())
# category queries {
#     logfile;
#     syslog_channel;
# };
print(category_security.model_bind_syntax())
# category security {
#     syslog_channel;
#     stderr_channel;
# };
print(category_default.model_bind_syntax())
# category default {
#     default_syslog;
#     logfile;
# };

logging_config = LoggingBlock(
    channels=[channel_file, channel_syslog, channel_stderr],
    categories=[category_queries, category_security],
)
logging_empty = LoggingBlock(channels=[], categories=[])
logging_channels_only = LoggingBlock(channels=[channel_file, channel_null], categories=[])
print(logging_config.model_bind_syntax())
# logging {
#     channel logfile {
#         file "/var/log/bind/query.log" versions 10 size 100M suffix timestamp;
#         buffered yes;
#         print-category yes;
#         print-severity yes;
#         print-time iso8601;
#         severity info;
#     };
#     channel stderr_channel {
#         stderr;
#         severity warning;
#     };
#     channel syslog_channel {
#         syslog daemon;
#         print-category no;
#         print-severity no;
#         print-time iso8601-utc;
#         severity debug 3;
#     };
#     category queries {
#         logfile;
#         syslog_channel;
#     };
#     category security {
#         syslog_channel;
#         stderr_channel;
#     };
# };
print(logging_empty.model_bind_syntax())
# logging { };
print(logging_channels_only.model_bind_syntax())
# logging {
#     channel logfile {
#         file "/var/log/bind/query.log" versions 10 size 100M suffix timestamp;
#         buffered yes;
#         print-category yes;
#         print-severity yes;
#         print-time iso8601;
#         severity info;
#     };
#     channel null_channel {
#         null;
#     };
# };

# NOTE: OPTIONS
server_1 = ServerSpecifier(address="192.168.1.1", port=53, key="my-key", tls="tls-config")
server_2 = ServerSpecifier(address=IPv6Address("2001:db8::1"), port="*", key=None, tls=None)
server_3 = ServerSpecifier(
    address=IPv4Address("10.0.0.1"), port="5353", key="tsig-key", tls="tls-profile"
)
print(server_1.model_bind_syntax())
# 192.168.1.1 port 53 key my-key tls tls-config;
print(server_2.model_bind_syntax())
# 2001:db8::1 port *;
print(server_3.model_bind_syntax())
# 10.0.0.1 port 5353 key tsig-key tls tls-profile;

also_notify1 = AlsoNotifyBlock(
    global_port=53,
    source="192.168.1.100",
    source_v6=IPv6Address("2001:db8::100"),
    servers=[server_1, server_2],
)
also_notify2 = AlsoNotifyBlock(global_port=800, source="*", source_v6="*", servers=[server_3])
print(also_notify1.model_bind_syntax())
# also-notify port 53 source 192.168.1.100 source-v6 2001:db8::100 {
#     192.168.1.1 port 53 key my-key tls tls-config;
#     2001:db8::1 port *;
# };
print(also_notify2.model_bind_syntax())
# also-notify port 800 source * source-v6 * {
#     10.0.0.1 port 5353 key tsig-key tls tls-profile;
# };

forwarders1 = ForwardersBlock(
    global_port=53,
    source="10.0.0.1",
    source_v6=IPv6Address("2001:db8::1"),
    servers=[server_1, server_2],
)
forwarders2 = ForwardersBlock(global_port=800, source="*", source_v6="*", servers=[server_3])
print(forwarders1.model_bind_syntax())
# forwarders port 53 source 10.0.0.1 source-v6 2001:db8::1 {
#     192.168.1.1 port 53 key my-key tls tls-config;
#     2001:db8::1 port *;
# };
print(forwarders2.model_bind_syntax())
# forwarders port 800 source * source-v6 * {
#     10.0.0.1 port 5353 key tsig-key tls tls-profile;
# };

dns64_1 = Dns64Block(
    prefix="64:ff9b::/96",
    break_dnssec="yes",
    clients=["192.168.1.0/24", "2001:db8::/32"],
    exclude=["192.168.1.100", IPv6Address("2001:db8::100")],
    recursive_only=1,
)
dns64_2 = Dns64Block(
    prefix=IPv6Network("2001:db8:64::/96"),
    mapped=["10.0.0.0/8", IPv4Network("172.16.0.0/12")],
    suffix="::ffff:0:0",
)
print(dns64_1.model_bind_syntax())
# dns64 64:ff9b::/96 {
#     break-dnssec yes;
#     clients {
#         192.168.1.0/24;
#         2001:db8::/32;
#     };
#     exclude {
#         192.168.1.100;
#         2001:db8::100;
#     };
#     recursive-only yes;
# };
print(dns64_2.model_bind_syntax())
# dns64 2001:db8:64::/96 {
#     mapped {
#         10.0.0.0/8;
#         172.16.0.0/12;
#     };
#     suffix ::ffff:0:0;
# };

rate_limit1 = RateLimitBlock(
    responses_per_second=100,
    errors_per_second=50,
    nxdomains_per_second=20,
    slip=2,
    exempt_clients=["127.0.0.1", "::1"],
    log_only=True,
)
rate_limit2 = RateLimitBlock(
    all_per_second=200, ipv4_prefix_length=24, ipv6_prefix_length=64, window=60, log_only="yes"
)
print(rate_limit1.model_bind_syntax())
# rate-limit {
#     errors-per-second 50;
#     exempt-clients {
#         127.0.0.1;
#         ::1;
#     };
#     log-only yes;
#     nxdomains-per-second 20;
#     responses-per-second 100;
#     slip 2;
# };
print(rate_limit2.model_bind_syntax())
# rate-limit {
#     all-per-second 200;
#     ipv4-prefix-length 24;
#     ipv6-prefix-length 64;
#     log-only yes;
#     window 60;
# };

rpz1 = ResponsePolicyZone(
    zone="example.com", add_soa=True, log=1, max_policy_ttl="1h", policy="drop", ede="blocked"
)
rpz2 = ResponsePolicyZone(
    zone="malware.local", recursive_only="no", nsip_enable=False, nsdname_enable=0
)
print(rpz1.model_bind_syntax())
# zone example.com {
#     add-soa yes;
#     ede blocked;
#     log yes;
#     max-policy-ttl 3600;
#     policy drop;
# };
print(rpz2.model_bind_syntax())
# zone malware.local {
#     nsdname-enable no;
#     nsip-enable no;
#     recursive-only no;
# };

response_policy = ResponsePolicyBlock(
    zones=[rpz1, rpz2], add_soa=True, break_dnssec=1, max_policy_ttl="2h", recursive_only=False
)
print(response_policy.model_bind_syntax())
# response-policy {
#     zone example.com {
#         add-soa yes;
#         ede blocked;
#         log yes;
#         max-policy-ttl 3600;
#         policy drop;
#     };
#     zone malware.local {
#         nsdname-enable no;
#         nsip-enable no;
#         recursive-only no;
#     };
#     add-soa yes;
#     break-dnssec yes;
#     max-policy-ttl 7200;
#     recursive-only no;
# };

catalog_zone = CatalogZoneBlock(
    zone="catalog.example.com",
    zone_directory="/var/lib/bind/catalog",
    in_memory="yes",
    min_update_interval="30m",
)
print(catalog_zone.model_bind_syntax())
# zone catalog.example.com {
#     in-memory yes;
#     min-update-interval 1800;
#     zone-directory "/var/lib/bind/catalog";
# };

rrset_rule1 = RrsetOrderRule(
    order_class="IN", order_type="A", order_name="example.com", order="random"
)
rrset_rule2 = RrsetOrderRule(order="fixed")
print(rrset_rule1.model_bind_syntax())
# class IN type A name "example.com" order random;
print(rrset_rule2.model_bind_syntax())
# order fixed;

options = OptionsBlock(
    allow_query=["any"],
    allow_query_on=["localhost"],
    allow_transfer=["192.168.1.0/24"],
    allow_update=["key tsig-key"],
    allow_notify=["secondary-servers"],
    allow_update_forwarding=["forwarders"],
    allow_query_cache=["trusted"],
    allow_query_cache_on=["localnets"],
    allow_recursion=["internal"],
    allow_recursion_on=["192.168.0.0/16"],
    blackhole=["spammers"],
    no_case_compress=["old-clients"],
    allow_new_zones=True,
    auth_nxdomain=1,
    flush_zones_on_shutdown="yes",
    root_key_sentinel=False,
    reuseport=0,
    message_compression=True,
    minimal_responses="no-auth",
    minimal_any=1,
    recursion="yes",
    request_nsid=True,
    require_server_cookie=False,
    answer_cookie=1,
    send_cookie="yes",
    stale_answer_enable=True,
    stale_cache_enable=False,
    dnssec_validation="auto",
    dnssec_accept_expired=0,
    querylog=True,
    zero_no_soa_ttl_cache=False,
    synth_from_dnssec="yes",
    check_dup_records="warn",
    check_integrity=True,
    check_mx="fail",
    check_mx_cname="ignore",
    check_sibling=False,
    check_spf="warn",
    check_srv_cname="fail",
    check_svcb=1,
    check_wildcard="yes",
    checkds="explicit",
    inline_signing=False,
    ixfr_from_differences=True,
    multi_master=0,
    notify="explicit",
    notify_to_soa=True,
    request_expire=False,
    try_tcp_refresh="yes",
    zero_no_soa_ttl=False,
    forward="first",
    forwarders=forwarders1,
    dual_stack_servers=[server_1, server_2],
    recursive_clients=1000,
    tcp_clients=150,
    clients_per_query=10,
    max_clients_per_query=100,
    fetches_per_zone=10,
    fetches_per_server=100,
    fetch_quota_params=[10, 20, 30],
    max_cache_size="90%",
    update_quota=100,
    sig0key_checks_limit=10,
    sig0message_checks_limit=5,
    max_journal_size="10M",
    max_records=10000,
    max_records_per_type=50,
    max_types_per_name=10,
    lame_ttl="10m",
    servfail_ttl="1m",
    min_ncache_ttl="5s",
    min_cache_ttl="1s",
    max_ncache_ttl="30m",
    max_cache_ttl="1d",
    max_stale_ttl="1h",
    dnssec_loadkeys_interval=60,
    nta_lifetime="1h",
    nta_recheck="10m",
    stale_answer_ttl="30s",
    stale_answer_client_timeout="disabled",
    stale_refresh_time="2h",
    nocookie_udp_size=512,
    cookie_algorithm="siphash24",
    cookie_secret=["secret1", "secret2"],
    serial_update_method="date",
    zone_statistics="full",
    edns_udp_size=512,
    max_udp_size=512,
    response_padding=(["any"], 128),
    masterfile_format="text",
    masterfile_style="full",
    max_query_count=100,
    max_recursion_depth=7,
    max_recursion_queries=100,
    max_query_restarts=10,
    notify_defer=30,
    notify_delay=5,
    max_rsa_exponent_size=2048,
    prefetch=(3, 10),
    v6_bias=100,
    version="My DNS Server",
    hostname="dns.example.com",
    server_id="hostname",
    empty_server="ns.example.com",
    empty_contact="admin.example.com",
    empty_zones_enable=True,
    disable_empty_zone=["localhost", "127.in-addr.arpa"],
    deny_answer_addresses=(["spoofers"], ["trusted.example.com"]),
    deny_answer_aliases=(["bad-alias.example.com"], ["good.example.com"]),
    nxdomain_redirect="redirect.example.com",
    directory="/etc/bind",
    key_directory="/etc/bind/keys",
    managed_keys_directory="/etc/bind/managed-keys",
    new_zones_directory="/etc/bind/new-zones",
    dnssec_policy="default",
    trust_anchor_telemetry=True,
    validate_except=["local", "intranet"],
    max_ixfr_ratio="100%",
    provide_ixfr=True,
    request_ixfr=False,
    qname_minimization="relaxed",
    check_names=[("primary", "fail"), ("secondary", "warn")],
    resolver_query_timeout=10000,
    resolver_use_dns64=True,
    ipv4only_enable=True,
    ipv4only_server="ns.example.com",
    ipv4only_contact="admin.example.com",
    dns64_server="ns.example.com",
    dns64_contact="admin.example.com",
    dns64_blocks=[dns64_1],
    disable_algorithms=[("example.com", ["RSASHA1", "DSA"])],
    disable_ds_digests=[("example.com", ["SHA-1"])],
    match_mapped_addresses=True,
    attach_cache="shared-cache",
    lmdb_mapsize="1G",
    rrset_order=[rrset_rule1, rrset_rule2],
    min_transfer_rate_in=(10240, 60),
    min_refresh_time=300,
    max_refresh_time=2419200,
    min_retry_time=500,
    max_retry_time=1209600,
    preferred_glue="A",
    sig_signing_nodes=100,
    sig_signing_signatures=10,
    sig_signing_type=65534,
    also_notify=also_notify1,
    rate_limit=rate_limit1,
    response_policy=response_policy,
    catalog_zones=[catalog_zone],
    pid_file="/var/run/named/named.pid",
    session_keyfile="/etc/bind/session.key",
    session_keyname="session-key",
    session_keyalg="hmac-sha256",
    port=53,
    tls_port=853,
    https_port=443,
    http_port=80,
    http_listener_clients=100,
    http_streams_per_connection=100,
    listen_on=["192.168.1.1", "10.0.0.1"],
    listen_on_v6=["2001:db8::1", "::1"],
    query_source="*",
    query_source_v6="*",
    transfer_source="192.168.1.100",
    transfer_source_v6="2001:db8::100",
    notify_source="*",
    notify_source_v6="*",
    parental_source="*",
    parental_source_v6="*",
    max_transfer_time_in=120,
    max_transfer_idle_in=60,
    max_transfer_time_out=120,
    max_transfer_idle_out=60,
    max_transfers_in=10,
    max_transfers_out=10,
    transfers_per_ns=2,
    notify_rate=20,
    startup_notify_rate=20,
    serial_query_rate=20,
    transfer_format="many-answers",
    transfer_message_size=65535,
    automatic_interface_scan=True,
    responselog=False,
    tcp_receive_buffer=65536,
    udp_receive_buffer=65536,
    tcp_send_buffer=65536,
    udp_send_buffer=65536,
    dnstap=["query", "response", "update"],
    dnstap_identity="dns-server",
    dnstap_version="1.0",
    fstrm_set_buffer_hint=4096,
    fstrm_set_flush_timeout=1000,
    fstrm_set_input_queue_size=10000,
    fstrm_set_output_notify_threshold=1000,
    fstrm_set_output_queue_model="mpsc",
    fstrm_set_output_queue_size=10000,
    fstrm_set_reopen_interval="5m",
    dump_file="/var/log/named_dump.db",
    memstatistics_file="/var/log/named.memstats",
    recursing_file="/var/log/named.recursing",
    statistics_file="/var/log/named.stats",
    secroots_file="/var/log/named.secroots",
    geoip_directory="/usr/share/GeoIP",
    interface_interval="60m",
    tcp_listen_queue=10,
    tcp_initial_timeout=300,
    tcp_idle_timeout=300,
    tcp_keepalive_timeout=300,
    tcp_advertised_timeout=300,
)
print(options.model_bind_syntax())
# options {
#     allow-new-zones yes;
#     allow-notify {
#         secondary-servers;
#     };
#     allow-query {
#         any;
#     };
#     allow-query-cache {
#         trusted;
#     };
#     allow-query-cache-on {
#         localnets;
#     };
#     allow-query-on {
#         localhost;
#     };
#     allow-recursion {
#         internal;
#     };
#     allow-recursion-on {
#         192.168.0.0/16;
#     };
#     allow-transfer {
#         192.168.1.0/24;
#     };
#     allow-update {
#         key tsig-key;
#     };
#     allow-update-forwarding {
#         forwarders;
#     };
#     also-notify port 53 source 192.168.1.100 source-v6 2001:db8::100 {
#         192.168.1.1 port 53 key my-key tls tls-config;
#         2001:db8::1 port *;
#     };
#     answer-cookie yes;
#     attach-cache shared-cache;
#     auth-nxdomain yes;
#     automatic-interface-scan yes;
#     blackhole {
#         spammers;
#     };
#     catalog-zones {
#         zone catalog.example.com {
#             in-memory yes;
#             min-update-interval 1800;
#             zone-directory "/var/lib/bind/catalog";
#         };
#     };
#     check-dup-records warn;
#     check-integrity yes;
#     check-mx fail;
#     check-mx-cname ignore;
#     check-names primary fail;
#     check-names secondary warn;
#     check-sibling no;
#     check-spf warn;
#     check-srv-cname fail;
#     check-svcb yes;
#     check-wildcard yes;
#     checkds explicit;
#     clients-per-query 10;
#     cookie-algorithm siphash24;
#     cookie-secret secret1;
#     cookie-secret secret2;
#     deny-answer-addresses {
#         spoofers;
#     } except-from {
#         trusted.example.com;
#     };
#     deny-answer-aliases {
#         bad-alias.example.com;
#     } except-from {
#         good.example.com;
#     };
#     directory "/etc/bind";
#     disable-algorithms example.com {
#         RSASHA1;
#         DSA;
#     };
#     disable-ds-digests example.com {
#         SHA-1;
#     };
#     disable-empty-zone {
#         127.in-addr.arpa;
#         localhost;
#     };
#     dns64 64:ff9b::/96 {
#         break-dnssec yes;
#         clients {
#             192.168.1.0/24;
#             2001:db8::/32;
#         };
#         exclude {
#             192.168.1.100;
#             2001:db8::100;
#         };
#         recursive-only yes;
#     };
#     dns64-contact admin.example.com;
#     dns64-server ns.example.com;
#     dnssec-accept-expired no;
#     dnssec-loadkeys-interval 60;
#     dnssec-policy default;
#     dnssec-validation auto;
#     dnstap {
#         query;
#         response;
#         update;
#     };
#     dnstap-identity "dns-server";
#     dnstap-version "1.0";
#     dual-stack-servers {
#         192.168.1.1 port 53 key my-key tls tls-config;
#         2001:db8::1 port *;
#     };
#     dump-file "/var/log/named_dump.db";
#     edns-udp-size 1232;
#     empty-contact admin.example.com;
#     empty-server ns.example.com;
#     empty-zones-enable yes;
#     fetch-quota-params 10 20 30;
#     fetches-per-server 100;
#     fetches-per-zone 10;
#     flush-zones-on-shutdown yes;
#     forward first;
#     forwarders port 53 source 10.0.0.1 source-v6 2001:db8::1 {
#         192.168.1.1 port 53 key my-key tls tls-config;
#         2001:db8::1 port *;
#     };
#     fstrm-set-buffer-hint 4096;
#     fstrm-set-flush-timeout 1000;
#     fstrm-set-input-queue-size 10000;
#     fstrm-set-output-notify-threshold 1000;
#     fstrm-set-output-queue-model mpsc;
#     fstrm-set-output-queue-size 10000;
#     fstrm-set-reopen-interval 300;
#     geoip-directory "/usr/share/GeoIP";
#     hostname "dns.example.com";
#     http-listener-clients 100;
#     http-port 80;
#     http-streams-per-connection 100;
#     https-port 443;
#     inline-signing no;
#     interface-interval 3600;
#     ipv4only-contact admin.example.com;
#     ipv4only-enable yes;
#     ipv4only-server ns.example.com;
#     ixfr-from-differences yes;
#     key-directory "/etc/bind/keys";
#     lame-ttl 600;
#     listen-on {
#         10.0.0.1;
#         192.168.1.1;
#     };
#     listen-on-v6 {
#         2001:db8::1;
#         ::1;
#     };
#     lmdb-mapsize 1G;
#     managed-keys-directory "/etc/bind/managed-keys";
#     masterfile-format text;
#     masterfile-style full;
#     match-mapped-addresses yes;
#     max-cache-size 90%;
#     max-cache-ttl 86400;
#     max-clients-per-query 100;
#     max-ixfr-ratio 100%;
#     max-journal-size 10M;
#     max-ncache-ttl 1800;
#     max-query-count 100;
#     max-query-restarts 10;
#     max-records 10000;
#     max-records-per-type 50;
#     max-recursion-depth 7;
#     max-recursion-queries 100;
#     max-refresh-time 2419200;
#     max-retry-time 1209600;
#     max-rsa-exponent-size 2048;
#     max-stale-ttl 3600;
#     max-transfer-idle-in 60;
#     max-transfer-idle-out 60;
#     max-transfer-time-in 120;
#     max-transfer-time-out 120;
#     max-transfers-in 10;
#     max-transfers-out 10;
#     max-types-per-name 10;
#     max-udp-size 1232;
#     memstatistics-file "/var/log/named.memstats";
#     message-compression yes;
#     min-cache-ttl 1;
#     min-ncache-ttl 5;
#     min-refresh-time 300;
#     min-retry-time 500;
#     min-transfer-rate-in 10240 60;
#     minimal-any yes;
#     minimal-responses no-auth;
#     multi-master no;
#     new-zones-directory "/etc/bind/new-zones";
#     no-case-compress {
#         old-clients;
#     };
#     nocookie-udp-size 512;
#     notify explicit;
#     notify-defer 30;
#     notify-delay 5;
#     notify-rate 20;
#     notify-source *;
#     notify-source-v6 *;
#     notify-to-soa yes;
#     nta-lifetime 3600;
#     nta-recheck 600;
#     nxdomain-redirect redirect.example.com;
#     parental-source *;
#     parental-source-v6 *;
#     pid-file "/var/run/named/named.pid";
#     port 53;
#     preferred-glue A;
#     prefetch 3 10;
#     provide-ixfr yes;
#     qname-minimization relaxed;
#     query-source *;
#     query-source-v6 *;
#     querylog yes;
#     rate-limit {
#         errors-per-second 50;
#         exempt-clients {
#             127.0.0.1;
#             ::1;
#         };
#         log-only yes;
#         nxdomains-per-second 20;
#         responses-per-second 100;
#         slip 2;
#     };
#     recursing-file "/var/log/named.recursing";
#     recursion yes;
#     recursive-clients 1000;
#     request-expire no;
#     request-ixfr no;
#     request-nsid yes;
#     require-server-cookie no;
#     resolver-query-timeout 10000;
#     resolver-use-dns64 yes;
#     response-padding {
#         any;
#     } block-size 128;
#     response-policy {
#         zone example.com {
#             add-soa yes;
#             ede blocked;
#             log yes;
#             max-policy-ttl 3600;
#             policy drop;
#         };
#         zone malware.local {
#             nsdname-enable no;
#             nsip-enable no;
#             recursive-only no;
#         };
#         add-soa yes;
#         break-dnssec yes;
#         max-policy-ttl 7200;
#         recursive-only no;
#     };
#     responselog no;
#     reuseport no;
#     root-key-sentinel no;
#     rrset-order {
#         class IN type A name "example.com" order random;
#         order fixed;
#     };
#     secroots-file "/var/log/named.secroots";
#     send-cookie yes;
#     serial-query-rate 20;
#     serial-update-method date;
#     server-id "hostname";
#     servfail-ttl 60;
#     session-keyalg hmac-sha256;
#     session-keyfile "/etc/bind/session.key";
#     session-keyname session-key;
#     sig0key-checks-limit 10;
#     sig0message-checks-limit 5;
#     sig-signing-nodes 100;
#     sig-signing-signatures 10;
#     sig-signing-type 65534;
#     stale-answer-client-timeout disabled;
#     stale-answer-enable yes;
#     stale-answer-ttl 30;
#     stale-cache-enable no;
#     stale-refresh-time 7200;
#     startup-notify-rate 20;
#     statistics-file "/var/log/named.stats";
#     synth-from-dnssec yes;
#     tcp-advertised-timeout 300;
#     tcp-clients 150;
#     tcp-idle-timeout 300;
#     tcp-initial-timeout 300;
#     tcp-keepalive-timeout 300;
#     tcp-listen-queue 10;
#     tcp-receive-buffer 65536;
#     tcp-send-buffer 65536;
#     tls-port 853;
#     transfer-format many-answers;
#     transfer-message-size 65535;
#     transfer-source 192.168.1.100;
#     transfer-source-v6 2001:db8::100;
#     transfers-per-ns 2;
#     trust-anchor-telemetry yes;
#     try-tcp-refresh yes;
#     udp-receive-buffer 65536;
#     udp-send-buffer 65536;
#     update-quota 100;
#     v6-bias 100;
#     validate-except {
#         intranet;
#         local;
#     };
#     version "My DNS Server";
#     zero-no-soa-ttl no;
#     zero-no-soa-ttl-cache no;
#     zone-statistics full;
# };

# NOTE: REMOTE SERVERS
server_entry_ipv4 = RemoteServerEntry(
    server="192.168.1.100", port=53, key="tsig-key-1", tls="tls-profile-1"
)
server_entry_ipv6 = RemoteServerEntry(
    server=IPv6Address("2001:db8::1"), port="*", key=None, tls="tls-profile-2"
)
server_entry_list = RemoteServerEntry(server="internal-dns-servers", key="shared-key", tls=None)
server_entry_ipv4_obj = RemoteServerEntry(server=IPv4Address("10.0.0.1"), port=5353, key="key-2")
print(server_entry_ipv4.model_bind_syntax())
# 192.168.1.100 port 53 key tsig-key-1 tls tls-profile-1;
print(server_entry_ipv6.model_bind_syntax())
# 2001:db8::1 port * tls tls-profile-2;
print(server_entry_list.model_bind_syntax())
# internal-dns-servers key shared-key;
print(server_entry_ipv4_obj.model_bind_syntax())
# 10.0.0.1 port 5353 key key-2;

remote_servers_mixed = RemoteServersBlock(
    name="primary-servers",
    port=53,
    source="192.168.1.100",
    source_v6=IPv6Address("2001:db8::100"),
    servers=[
        RemoteServerEntry(server="192.0.2.1", port=53),
        RemoteServerEntry(server=IPv4Address("198.51.100.1"), port="*"),
        RemoteServerEntry(server="2001:db8::2", key="auth-key"),
        RemoteServerEntry(server=IPv6Address("2001:db8::3"), tls="secure-tls"),
    ],
)
remote_servers_lists = RemoteServersBlock(
    name="backup-servers",
    port=5353,
    source="*",
    source_v6="*",
    servers=[
        RemoteServerEntry(server="secondary-dns-pool"),
        RemoteServerEntry(server="tertiary-dns-pool", key="backup-key"),
    ],
)
remote_servers_minimal = RemoteServersBlock(
    name="minimal-servers",
    servers=[RemoteServerEntry(server="192.168.0.1"), RemoteServerEntry(server="10.0.0.1")],
)
print(remote_servers_mixed.model_bind_syntax())
# remote-servers primary-servers port 53 source 192.168.1.100 source-v6 2001:db8::100 {
#     192.0.2.1 port 53;
#     198.51.100.1 port *;
#     2001:db8::2 key auth-key;
#     2001:db8::3 tls secure-tls;
# };
print(remote_servers_lists.model_bind_syntax())
# remote-servers backup-servers port 5353 source * source-v6 * {
#     secondary-dns-pool;
#     tertiary-dns-pool key backup-key;
# };
print(remote_servers_minimal.model_bind_syntax())
# remote-servers minimal-servers {
#     10.0.0.1;
#     192.168.0.1;
# };

# NOTE: SERVER
server_minimal = ServerBlock(netprefix="192.168.1.0/24", bogus=True)
server_mixed = ServerBlock(
    netprefix=IPv4Network("10.0.0.0/8"),
    bogus=1,
    edns="yes",
    provide_ixfr=False,
    request_expire=0,
    request_ixfr="no",
    request_nsid=True,
    require_cookie=1,
    send_cookie="yes",
    tcp_keepalive=False,
    tcp_only=0,
    edns_udp_size=512,
    edns_version=0,
    max_udp_size=512,
    padding=128,
    transfers=10,
    transfer_format="many-answers",
    keys="tsig-key",
    notify_source="192.168.1.100",
    notify_source_v6=IPv6Address("2001:db8::100"),
    query_source="*",
    query_source_v6="*",
    transfer_source="192.168.1.1",
    transfer_source_v6="2001:db8::1",
)
server_tcp_only = ServerBlock(
    netprefix=IPv6Network("2001:db8::/32"),
    tcp_only="yes",
    tcp_keepalive=True,
    request_ixfr=1,
    require_cookie="yes",
    keys="secure-key",
    notify_source="*",
    notify_source_v6="*",
    query_source=IPv4Address("10.0.0.1"),
    query_source_v6=IPv6Address("2001:db8::1"),
    transfer_format="one-answer",
)
print(server_minimal.model_bind_syntax())
# server 192.168.1.0/24 {
#     bogus yes;
# };
print(server_mixed.model_bind_syntax())
# server 10.0.0.0/8 {
#     bogus yes;
#     edns yes;
#     edns-udp-size 512;
#     edns-version 0;
#     keys tsig-key;
#     max-udp-size 512;
#     notify-source 192.168.1.100;
#     notify-source-v6 2001:db8::100;
#     padding 128;
#     provide-ixfr no;
#     query-source *;
#     query-source-v6 *;
#     request-expire no;
#     request-ixfr no;
#     request-nsid yes;
#     require-cookie yes;
#     send-cookie yes;
#     tcp-keepalive no;
#     tcp-only no;
#     transfer-format many-answers;
#     transfer-source 192.168.1.1;
#     transfer-source-v6 2001:db8::1;
#     transfers 10;
# };
print(server_tcp_only.model_bind_syntax())
# server 2001:db8::/32 {
#     keys secure-key;
#     notify-source *;
#     notify-source-v6 *;
#     query-source 10.0.0.1;
#     query-source-v6 2001:db8::1;
#     request-ixfr yes;
#     require-cookie yes;
#     tcp-keepalive yes;
#     tcp-only yes;
#     transfer-format one-answer;
# };

# NOTE: STATISTICS CHANNELS
channel_ipv4 = InetChannel(
    address="127.0.0.1", port=80, allow=["localhost", "127.0.0.1", "192.168.1.0/24"]
)
channel_ipv6 = InetChannel(
    address=IPv6Address("::1"),
    port="*",
    allow=[IPv4Network("10.0.0.0/8"), "2001:db8::/32", "key admin-key"],
)
channel_wildcard = InetChannel(address="*", port=8080, allow=None)
channel_ipv6_wildcard = InetChannel(address="::", port=80, allow=["any"])
print(channel_ipv4.model_bind_syntax())
# inet 127.0.0.1 port 80 allow {
#     127.0.0.1;
#     192.168.1.0/24;
#     localhost;
# };
print(channel_ipv6.model_bind_syntax())
# inet ::1 port * allow {
#     10.0.0.0/8;
#     2001:db8::/32;
#     key admin-key;
# };
print(channel_wildcard.model_bind_syntax())
# inet * port 8080;
print(channel_ipv6_wildcard.model_bind_syntax())
# inet :: port 80 allow {
#     any;
# };

stats_channels_full = StatisticsChannelsBlock(
    channels=[
        channel_ipv4,
        channel_ipv6,
        InetChannel(address="192.168.1.100", port=8080, allow=["192.168.1.0/24"]),
    ]
)
stats_channels_single = StatisticsChannelsBlock(
    channels=[InetChannel(address="*", port=80, allow=["any"])]
)
stats_channels_mixed = StatisticsChannelsBlock(
    channels=[
        InetChannel(address="127.0.0.1", port="*", allow=["localhost"]),
        InetChannel(address=IPv6Address("2001:db8::1"), port=8080, allow=None),
        InetChannel(address="::", port=80, allow=["any"]),
    ]
)
print(stats_channels_full.model_bind_syntax())
# statistics-channels {
#     inet 127.0.0.1 port 80 allow {
#         127.0.0.1;
#         192.168.1.0/24;
#         localhost;
#     };
#     inet 192.168.1.100 port 8080 allow {
#         192.168.1.0/24;
#     };
#     inet ::1 port * allow {
#         10.0.0.0/8;
#         2001:db8::/32;
#         key admin-key;
#     };
# };
print(stats_channels_single.model_bind_syntax())
# statistics-channels {
#     inet * port 80 allow {
#         any;
#     };
# };
print(stats_channels_mixed.model_bind_syntax())
# statistics-channels {
#     inet 127.0.0.1 port * allow {
#         localhost;
#     };
#     inet 2001:db8::1 port 8080;
#     inet :: port 80 allow {
#         any;
#     };
# };

# NOTE: TLS
tls_ephemeral = TlsBlock(name="ephemeral")
tls_none = TlsBlock(name="none")
tls_minimal = TlsBlock(
    name="minimal-tls",
    key_file='"/etc/bind/tls/server.key"',
    cert_file='"/etc/bind/tls/server.crt"',
)
tls_full = TlsBlock(
    name="secure-tls",
    key_file="/etc/bind/tls/private.key",
    cert_file="/etc/bind/tls/certificate.crt",
    ca_file="/etc/bind/tls/ca-bundle.crt",
    dhparam_file="/etc/bind/tls/dhparam.pem",
    ciphers="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256",
    protocols=["TLSv1.2", "TLSv1.3"],
    prefer_server_ciphers=True,
    session_tickets="no",
    remote_hostname="dns.example.com",
)
tls_mixed = TlsBlock(
    name="mixed-tls",
    key_file='"tls/key.pem"',
    cert_file='"tls/cert.pem"',
    ca_file='"tls/ca.crt"',
    protocols=["TLSv1.3"],
    prefer_server_ciphers=1,
    session_tickets=0,
    remote_hostname='"remote.example.com"',
)
print(tls_ephemeral.model_bind_syntax())
# tls ephemeral {};
print(tls_none.model_bind_syntax())
# tls none {};
print(tls_minimal.model_bind_syntax())
# tls minimal-tls {
#     cert-file "/etc/bind/tls/server.crt";
#     key-file "/etc/bind/tls/server.key";
# };
print(tls_full.model_bind_syntax())
# tls secure-tls {
#     ca-file "/etc/bind/tls/ca-bundle.crt";
#     cert-file "/etc/bind/tls/certificate.crt";
#     ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;
#     dhparam-file "/etc/bind/tls/dhparam.pem";
#     key-file "/etc/bind/tls/private.key";
#     prefer-server-ciphers yes;
#     protocols {
#         TLSv1.2;
#         TLSv1.3;
#     };
#     remote-hostname "dns.example.com";
#     session-tickets no;
# };
print(tls_mixed.model_bind_syntax())
# tls mixed-tls {
#     ca-file "tls/ca.crt";
#     cert-file "tls/cert.pem";
#     key-file "tls/key.pem";
#     prefer-server-ciphers yes;
#     protocols {
#         TLSv1.3;
#     };
#     remote-hostname "remote.example.com";
#     session-tickets no;
# };

# NOTE: TRUST ANCHORS
key_anchor_static = KeyTrustAnchor(
    domain="example.com",
    anchor_type=AnchorTypeEnum.STATIC_KEY,
    flags=257,
    protocol=3,
    algorithm=8,
    key_data='"AwEAAcFcGsaxxdKkuJ..."',
)
key_anchor_initial = KeyTrustAnchor(
    domain="root-servers.net",
    anchor_type=AnchorTypeEnum.INITIAL_KEY,
    flags=256,
    protocol=3,
    algorithm=13,
    key_data='"AwEAAaz/tAm8yTn4..."',
)
key_anchor_ed25519 = KeyTrustAnchor(
    domain="secure.example.com",
    anchor_type=AnchorTypeEnum.INITIAL_KEY,
    flags=257,
    protocol=3,
    algorithm=15,
    key_data='"AwEAAcVNPM7Rf..."',
)
print(key_anchor_static.model_bind_syntax())
# example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
print(key_anchor_initial.model_bind_syntax())
# root-servers.net initial-key 256 3 13 "AwEAAaz/tAm8yTn4...";
print(key_anchor_ed25519.model_bind_syntax())
# secure.example.com initial-key 257 3 15 "AwEAAcVNPM7Rf...";

ds_anchor_static = DSTrustAnchor(
    domain="example.org",
    anchor_type=AnchorTypeEnum.STATIC_DS,
    key_tag=12345,
    algorithm=8,
    digest_type=2,
    digest='"2BB183AF5F225"',
)
ds_anchor_initial = DSTrustAnchor(
    domain="dnssec.test",
    anchor_type=AnchorTypeEnum.INITIAL_DS,
    key_tag=54321,
    algorithm=13,
    digest_type=3,
    digest='"4CDB3E8D0A0F"',
)
ds_anchor_sha512 = DSTrustAnchor(
    domain="secure.org",
    anchor_type=AnchorTypeEnum.INITIAL_DS,
    key_tag=65535,
    algorithm=14,
    digest_type=4,
    digest='"ABCDEF123456"',
)
print(ds_anchor_static.model_bind_syntax())
# example.org static-ds 12345 8 2 "2BB183AF5F225";
print(ds_anchor_initial.model_bind_syntax())
# dnssec.test initial-ds 54321 13 3 "4CDB3E8D0A0F";
print(ds_anchor_sha512.model_bind_syntax())
# secure.org initial-ds 65535 14 4 "ABCDEF123456";

trust_anchors_keys = TrustAnchorsBlock(anchors=[key_anchor_static, key_anchor_ed25519])
trust_anchors_ds = TrustAnchorsBlock(anchors=[ds_anchor_static, ds_anchor_sha512])
trust_anchors_mixed = TrustAnchorsBlock(
    anchors=[key_anchor_static, key_anchor_initial, ds_anchor_static, ds_anchor_initial]
)
print(trust_anchors_keys.model_bind_syntax())
# trust-anchors {
#     secure.example.com initial-key 257 3 15 "AwEAAcVNPM7Rf...";
#     example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
# };
print(trust_anchors_ds.model_bind_syntax())
# trust-anchors {
#     secure.org initial-ds 65535 14 4 "ABCDEF123456";
#     example.org static-ds 12345 8 2 "2BB183AF5F225";
# };
print(trust_anchors_mixed.model_bind_syntax())
# trust-anchors {
#     dnssec.test initial-ds 54321 13 3 "4CDB3E8D0A0F";
#     root-servers.net initial-key 256 3 13 "AwEAAaz/tAm8yTn4...";
#     example.org static-ds 12345 8 2 "2BB183AF5F225";
#     example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
# };

# NOTE: RESOURCE RECORDS
a_record1 = ARecord(name="example.com", ttl=3600, address="192.168.1.1")
a_record2 = ARecord(name="server.example.com", ttl="1h", address=IPv4Address("10.0.0.1"))
print(a_record1.model_bind_syntax())
# example.com                             3600     IN   A          192.168.1.1
print(a_record2.model_bind_syntax())
# server.example.com                      3600     IN   A          10.0.0.1

aaaa_record1 = AAAARecord(name="ipv6.example.com", ttl=7200, address="2001:db8::1")
aaaa_record2 = AAAARecord(name="server6.example.com", ttl="2h", address=IPv6Address("fe80::1"))
print(aaaa_record1.model_bind_syntax())
# ipv6.example.com                        7200     IN   AAAA       2001:db8::1
print(aaaa_record2.model_bind_syntax())
# server6.example.com                     7200     IN   AAAA       fe80::1

cname_record1 = CNAMERecord(name="www.example.com", ttl=3600, canonical_name="example.com")
cname_record2 = CNAMERecord(
    name="alias.example.com", ttl="30m", canonical_name="server.example.com"
)
print(cname_record1.model_bind_syntax())
# www.example.com                         3600     IN   CNAME      example.com
print(cname_record2.model_bind_syntax())
# alias.example.com                       1800     IN   CNAME      server.example.com

mx_record1 = MXRecord(name="example.com", ttl=3600, preference=10, exchange="mail.example.com")
mx_record2 = MXRecord(name="example.com", ttl="1h", preference=20, exchange="mail2.example.com")
print(mx_record1.model_bind_syntax())
# example.com                             3600     IN   MX         10 mail.example.com
print(mx_record2.model_bind_syntax())
# example.com                             3600     IN   MX         20 mail2.example.com

ns_record1 = NSRecord(name="example.com", ttl=86400, nsdname="ns1.example.com")
ns_record2 = NSRecord(name="example.com", ttl="1d", nsdname="ns2.example.com")
print(ns_record1.model_bind_syntax())
# example.com                             86400    IN   NS         ns1.example.com
print(ns_record2.model_bind_syntax())
# example.com                             86400    IN   NS         ns2.example.com

soa_record1 = SOARecord(
    name="example.com",
    ttl=3600,
    mname="ns1.example.com",
    rname="admin.example.com",
    serial=2024010101,
    refresh="3h",
    retry="1h",
    expire="1w",
    minimum="1h",
)
soa_record2 = SOARecord(
    origin="example.com",
    ttl="1d",
    mname="ns.example.com",
    rname="hostmaster.example.com",
    serial="2024010102",
    refresh=10800,
    retry=3600,
    expire=604800,
    minimum=3600,
)
print(soa_record1.model_bind_syntax())
# $TTL 3600
# example.com                                       IN  SOA ns1.example.com admin.example.com (
#                                                                  2024010101 ; Serial number (YYYYMMDDNN)
#                                                                  3h         ; Refresh time
#                                                                  1h         ; Retry time
#                                                                  1w         ; Expire time
#                                                                  1h         ; Minimum TTL
#                                                       )
print(soa_record2.model_bind_syntax())
# $TTL 86400
# $ORIGIN example.com
# @                                                 IN  SOA ns.example.com hostmaster.example.com (
#                                                                  2024010102 ; Serial number (YYYYMMDDNN)
#                                                                  10800      ; Refresh time
#                                                                  3600       ; Retry time
#                                                                  604800     ; Expire time
#                                                                  3600       ; Minimum TTL
#                                                       )

txt_record1 = TXTRecord(name="example.com", ttl=3600, text_data=['"v=spf1 mx ~all"'])
txt_record2 = TXTRecord(
    name="_dmarc.example.com",
    ttl="1h",
    text_data=['"v=DMARC1; p=none; rua=mailto:dmarc@example.com"'],
)
print(txt_record1.model_bind_syntax())
# example.com                             3600     IN   TXT        "v=spf1 mx ~all"
print(txt_record2.model_bind_syntax())
# _dmarc.example.com                      3600     IN   TXT        "v=DMARC1; p=none; rua=mailto:dmarc@example.com"

srv_record1 = SRVRecord(
    name="_sip._tcp.example.com",
    ttl=3600,
    priority=0,
    weight=5,
    port=5060,
    target="sip.example.com",
)
srv_record2 = SRVRecord(
    name="_ldap._tcp.example.com",
    ttl="2h",
    priority=0,
    weight=100,
    port="389",
    target="ldap.example.com",
)
print(srv_record1.model_bind_syntax())
# _sip._tcp.example.com                   3600     IN   SRV        0 5 5060 sip.example.com
print(srv_record2.model_bind_syntax())
# _ldap._tcp.example.com                  7200     IN   SRV        0 100 389 ldap.example.com

ds_record1 = DSRecord(
    name="example.com",
    ttl=3600,
    key_tag=12345,
    algorithm=DNSSECAlgorithmEnum.RSASHA256,
    digest_type=2,
    digest="2BB183AF5F225...",
)
ds_record2 = DSRecord(
    name="example.com",
    ttl="1h",
    key_tag=54321,
    algorithm=DNSSECAlgorithmEnum.ECDSAP256SHA256,
    digest_type=1,
    digest="ABCDEF123456...",
)
print(ds_record1.model_bind_syntax())
# example.com                             3600     IN   DS         12345 8 2 2BB183AF5F225...
print(ds_record2.model_bind_syntax())
# example.com                             3600     IN   DS         54321 13 1 ABCDEF123456...

dnskey_record1 = DNSKEYRecord(
    name="example.com",
    ttl=3600,
    flags=256,
    protocol=3,
    algorithm=DNSSECAlgorithmEnum.ECDSAP256SHA256,
    public_key="AwEAAcFcGsaxxdKkuJ...",
)
dnskey_record2 = DNSKEYRecord(
    name="example.com",
    ttl="1h",
    flags=257,
    protocol=3,
    algorithm=DNSSECAlgorithmEnum.RSASHA256,
    public_key="AwEAAaz/tAm8yTn4...",
)
print(dnskey_record1.model_bind_syntax())
# example.com                             3600     IN   DNSKEY     256 3 13 AwEAAcFcGsaxxdKkuJ...
print(dnskey_record2.model_bind_syntax())
# example.com                             3600     IN   DNSKEY     257 3 8 AwEAAaz/tAm8yTn4...

rrsig_record1 = RRSIGRecord(
    name="example.com",
    ttl=3600,
    type_covered="A",
    algorithm=DNSSECAlgorithmEnum.RSASHA256,
    labels=2,
    original_ttl=3600,
    signature_expiration=4294967295,
    signature_inception=4294967295,
    key_tag=12345,
    signer_name="example.com",
    signature="AwEAAcFcGsaxxdKkuJ...",
)
rrsig_record2 = RRSIGRecord(
    name="example.com",
    ttl="1h",
    type_covered="DNSKEY",
    algorithm=DNSSECAlgorithmEnum.ECDSAP256SHA256,
    labels=2,
    original_ttl="1h",
    signature_expiration="4294967295",
    signature_inception="4294967295",
    key_tag=54321,
    signer_name="example.com",
    signature="ABCDEF123456...",
)
print(rrsig_record1.model_bind_syntax())
# example.com                             3600     IN   RRSIG      A 8 2 3600 4294967295 4294967295 12345 example.com AwEAAcFcGsaxxdKkuJ...
print(rrsig_record2.model_bind_syntax())
# example.com                             3600     IN   RRSIG      DNSKEY 13 2 3600 4294967295 4294967295 54321 example.com ABCDEF123456...

sshfp_record1 = SSHFPRecord(
    name="server.example.com",
    ttl=3600,
    algorithm=SSHFPAlgorithmEnum.RSA,
    hash_type=SSHFPHashTypeEnum.SHA256,
    fingerprint="1234567890ABCDEF...",
)

sshfp_record2 = SSHFPRecord(
    name="server.example.com",
    ttl="1h",
    algorithm=SSHFPAlgorithmEnum.ED25519,
    hash_type=SSHFPHashTypeEnum.SHA256,
    fingerprint="FEDCBA0987654321...",
)
print(sshfp_record1.model_bind_syntax())
# server.example.com                      3600     IN   SSHFP      1 2 1234567890ABCDEF...
print(sshfp_record2.model_bind_syntax())
# server.example.com                      3600     IN   SSHFP      4 2 FEDCBA0987654321...

tlsa_record1 = TLSARecord(
    name="_443._tcp.example.com",
    ttl=3600,
    cert_usage=TLSACertUsageEnum.DANE_EE,
    selector=TLSASelectorEnum.FULL_CERT,
    matching_type=TLSAMatchingTypeEnum.SHA256,
    cert_data="ABCDEF123456",
)
tlsa_record2 = TLSARecord(
    name="_25._tcp.mail.example.com",
    ttl="1h",
    cert_usage=TLSACertUsageEnum.DANE_EE,
    selector=TLSASelectorEnum.SUBJECT_PUBLIC_KEY_INFO,
    matching_type=TLSAMatchingTypeEnum.SHA512,
    cert_data="1234567890ABCDEF",
)
print(tlsa_record1.model_bind_syntax())
# _443._tcp.example.com                   3600     IN   TLSA       3 0 1 ABCDEF123456
print(tlsa_record2.model_bind_syntax())
# _25._tcp.mail.example.com               3600     IN   TLSA       3 1 2 1234567890ABCDEF

caa_record1 = CAARecord(
    name="example.com", ttl=3600, flags=0, tag=CAATagEnum.ISSUE, value='"letsencrypt.org"'
)
caa_record2 = CAARecord(
    name="example.com",
    ttl="1h",
    flags=128,
    tag=CAATagEnum.ISSUEWILD,
    value='"digicert.com; policy=ev"',
)
print(caa_record1.model_bind_syntax())
# example.com                             3600     IN   CAA        0 issue "letsencrypt.org"
print(caa_record2.model_bind_syntax())
# example.com                             3600     IN   CAA        128 issuewild "digicert.com; policy=ev"

# NOTE: ZONE
update_rule1 = UpdatePolicyRule(
    action="grant",
    identity="key admin-key",
    rule_type=UpdatePolicyRuleTypeEnum.SUBDOMAIN,
    name="admin.example.com",
    record_types=["A", "AAAA", "MX"],
)
update_rule2 = UpdatePolicyRule(
    action="deny", identity="*", rule_type=UpdatePolicyRuleTypeEnum.WILDCARD, record_types=["ANY"]
)
print(update_rule1.model_bind_syntax())
# grant key admin-key subdomain admin.example.com A AAAA MX;
print(update_rule2.model_bind_syntax())
# deny * wildcard ANY;

update_policy_local = UpdatePolicyBlock(local="yes")
update_policy_rules = UpdatePolicyBlock(rules=[update_rule1, update_rule2])
print(update_policy_local.model_bind_syntax())
# update-policy local;
print(update_policy_rules.model_bind_syntax())
# update-policy {
#     grant key admin-key subdomain admin.example.com A AAAA MX;
#     deny * wildcard ANY;
# };

primary_zone = ZoneBlock(
    name="example.com",
    zone_type=ZoneTypeEnum.PRIMARY,
    zone_class=ZoneClassEnum.IN,
    file="/var/lib/bind/db.example.com",
    allow_query=["any"],
    allow_transfer=["secondary-servers"],
    allow_update=["key dhcp-key"],
    check_names="warn",
    masterfile_format="text",
    masterfile_style="full",
    dnssec_policy="default",
    update_policy=update_policy_rules,
    notify="yes",
    also_notify=[("192.168.1.100", 53), ("2001:db8::1", 53), "secondary.example.com"],
    resource_records=[
        SOARecord(
            name="example.com",
            mname="ns1.example.com",
            rname="admin.example.com",
            serial=2024010101,
            refresh=10800,
            retry=3600,
            expire=604800,
            minimum=3600,
        ),
        NSRecord(name="example.com", nsdname="ns1.example.com"),
        NSRecord(name="example.com", nsdname="ns2.example.com"),
        ARecord(name="example.com", address="192.168.1.1"),
        AAAARecord(name="example.com", address="2001:db8::1"),
        MXRecord(name="example.com", preference=10, exchange="mail.example.com"),
        ARecord(name="www.example.com", address="192.168.1.2"),
        CNAMERecord(name="alias.example.com", canonical_name="www.example.com"),
    ],
)
secondary_zone = ZoneBlock(
    name="secondary.example.com",
    zone_type=ZoneTypeEnum.SECONDARY,
    file="/var/lib/bind/db.secondary.example.com",
    primaries=[("192.168.1.1", 53), ("2001:db8::1", 53), "primary.example.com"],
    allow_transfer=["none"],
    allow_notify=["192.168.1.1"],
    max_transfer_time_in=120,
    max_transfer_idle_in=60,
)
forward_zone = ZoneBlock(
    name="forward.example.com",
    zone_type=ZoneTypeEnum.FORWARD,
    forward="only",
    forwarders=["8.8.8.8", IPv4Address("8.8.4.4"), IPv6Address("2001:4860:4860::8888")],
)
hint_zone = ZoneBlock(
    name=".",
    zone_type=ZoneTypeEnum.HINT,
    file="/var/lib/bind/db.root",
    resource_records=[
        ARecord(name="a.root-servers.net", address="198.41.0.4"),
        AAAARecord(name="a.root-servers.net", address="2001:503:ba3e::2:30"),
    ],
)
static_stub_zone = ZoneBlock(
    name="static.example.com",
    zone_type=ZoneTypeEnum.STATIC_STUB,
    server_addresses=["192.168.1.100", "10.0.0.100"],
    server_names=["ns1.static.example.com", "ns2.static.example.com"],
)
print(primary_zone.model_bind_syntax())
# zone example.com {
#     type primary;
#     allow-query {
#         any;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     allow-update {
#         key dhcp-key;
#     };
#     also-notify {
#         192.168.1.100 port 53;
#         2001:db8::1 port 53;
#         secondary.example.com;
#     };
#     check-names warn;
#     dnssec-policy default;
#     file "/var/lib/bind/db.example.com";
#     masterfile-format text;
#     masterfile-style full;
#     notify yes;
#     update-policy {
#         grant key admin-key subdomain admin.example.com A AAAA MX;
#         deny * wildcard ANY;
#     };
# };
print(secondary_zone.model_bind_syntax())
# zone secondary.example.com {
#     type secondary;
#     allow-notify {
#         192.168.1.1;
#     };
#     allow-transfer {
#         none;
#     };
#     file "/var/lib/bind/db.secondary.example.com";
#     max-transfer-idle-in 60;
#     max-transfer-time-in 120;
#     primaries {
#         192.168.1.1 port 53;
#         2001:db8::1 port 53;
#         primary.example.com;
#     };
# };
print(forward_zone.model_bind_syntax())
# zone forward.example.com {
#     type forward;
#     forward only;
#     forwarders {
#         2001:4860:4860::8888;
#         8.8.4.4;
#         8.8.8.8;
#     };
# };
print(hint_zone.model_bind_syntax())
# zone . {
#     type hint;
#     file "/var/lib/bind/db.root";
# };
print(static_stub_zone.model_bind_syntax())
# zone static.example.com {
#     type static-stub;
#     server-addresses {
#         10.0.0.100;
#         192.168.1.100;
#     };
#     server-names {
#         ns1.static.example.com;
#         ns2.static.example.com;
#     };
# };

print(primary_zone.model_bind_syntax_zone_file())
# example.com                                      IN   SOA ns1.example.com admin.example.com (
#                                                                  2024010101 ; Serial number (YYYYMMDDNN)
#                                                                  10800      ; Refresh time
#                                                                  3600       ; Retry time
#                                                                  604800     ; Expire time
#                                                                  3600       ; Minimum TTL
#                                                       )
# example.com                                      IN   NS         ns1.example.com
# example.com                                      IN   NS         ns2.example.com
# example.com                                      IN   MX         10 mail.example.com
# example.com                                      IN   A          192.168.1.1
# www.example.com                                  IN   A          192.168.1.2
# example.com                                      IN   AAAA       2001:db8::1
# alias.example.com                                IN   CNAME      www.example.com

# NOTE: VIEW
view_minimal = ViewBlock(name="internal-view", match_clients=["192.168.0.0/16", "10.0.0.0/8"])
view_non_in = ViewBlock(
    name="chaos-view",
    view_class=ZoneClassEnum.CHAOS,
    match_clients=["any"],
    view_zones=[ZoneBlock(name=".", zone_type=ZoneTypeEnum.HINT, file="/etc/bind/db.root")],
)
view_full = ViewBlock(
    name="secure-view",
    match_clients=["trusted-nets", "key secure-key"],
    match_destinations=["any"],
    match_recursive_only=True,
    server_blocks=[
        ServerBlock(
            netprefix="192.168.1.0/24", bogus=1, edns="yes", provide_ixfr=False, request_ixfr="no"
        ),
        ServerBlock(
            netprefix=IPv4Network("10.0.0.0/8"),
            tcp_only=True,
            request_nsid=1,
            require_cookie="yes",
        ),
    ],
    key_blocks=[
        KeyBlock(name="tsig-key", algorithm="hmac-sha256", secret="aGVsbG8td29ybGQ="),
        KeyBlock(name='"secure-key"', algorithm="hmac-sha512", secret='"dGhpcy1pc2FzZWNyZXQ="'),
    ],
    trust_anchors=[
        TrustAnchorsBlock(
            anchors=[
                KeyTrustAnchor(
                    domain="example.com",
                    anchor_type=AnchorTypeEnum.STATIC_KEY,
                    flags=257,
                    protocol=3,
                    algorithm=8,
                    key_data='"AwEAAcFcGsaxxdKkuJ..."',
                )
            ]
        )
    ],
    dnssec_policy_block=DnssecPolicyBlock(
        name="policy_mixed",
        manual_mode=0,
        offline_ksk=False,
        parent_propagation_delay=3600,
        publish_safety="PT1H",
        signatures_refresh="5D",
        cds_digest_types=[DnssecDigestTypeEnum.SHA256, DnssecDigestTypeEnum.SHA384],
        keys=[key_zsk],
    ),
    view_zones=[
        ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/lib/bind/db.example.com",
            allow_query=["any"],
            dnssec_policy="default",
        ),
        ZoneBlock(
            name="secondary.example.com",
            zone_type=ZoneTypeEnum.SECONDARY,
            primaries=[("192.168.1.1", 53)],
            file="/var/lib/bind/db.secondary",
        ),
    ],
    recursion="yes",
    allow_query=["any"],
    allow_transfer=["secondary-servers"],
    dnssec_validation="auto",
    querylog=True,
)
print(view_minimal.model_bind_syntax())
# view internal-view {
#     match-clients {
#         10.0.0.0/8;
#         192.168.0.0/16;
#     };
# };
print(view_non_in.model_bind_syntax())
# view chaos-view CHAOS {
#     match-clients {
#         any;
#     };
#     zone . {
#         type hint;
#         file "/etc/bind/db.root";
#     };
# };
print(view_full.model_bind_syntax())
# view secure-view {
#     allow-query {
#         any;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     dnssec-policy policy_mixed {
#         cds-digest-types {
#             SHA-256;
#             SHA-384;
#         };
#         keys {
#             zsk lifetime unlimited algorithm ecdsap384sha384;
#         };
#         manual-mode no;
#         offline-ksk no;
#         parent-propagation-delay 3600;
#         publish-safety 3600;
#         signatures-refresh 432000;
#     };
#     dnssec-validation auto;
#     key-blocks {
#         key "tsig-key" {
#             algorithm hmac-sha256;
#             secret "aGVsbG8td29ybGQ=";
#         };
#         key "secure-key" {
#             algorithm hmac-sha512;
#             secret "dGhpcy1pc2FzZWNyZXQ=";
#         };
#     };
#     match-clients {
#         key secure-key;
#         trusted-nets;
#     };
#     match-destinations {
#         any;
#     };
#     match-recursive-only yes;
#     querylog yes;
#     recursion yes;
#     server-blocks {
#         server 192.168.1.0/24 {
#             bogus yes;
#             edns yes;
#             provide-ixfr no;
#             request-ixfr no;
#         };
#         server 10.0.0.0/8 {
#             request-nsid yes;
#             require-cookie yes;
#             tcp-only yes;
#         };
#     };
#     trust-anchors {
#         trust-anchors {
#             example.com static-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
#         };
#     };
#     zone example.com {
#         type primary;
#         allow-query {
#             any;
#         };
#         dnssec-policy default;
#         file "/var/lib/bind/db.example.com";
#     };
#     zone secondary.example.com {
#         type secondary;
#         file "/var/lib/bind/db.secondary";
#         primaries {
#             192.168.1.1 port 53;
#         };
#     };
# };

# NOTE: NAMED CONFIG
minimal_config = NamedConfig(
    options_block=OptionsBlock(
        directory="/etc/bind",
        recursion="yes",
        allow_recursion=["localhost", "localnets"],
        listen_on=["any"],
        listen_on_v6=["any"],
    ),
    zone_blocks=[
        ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/etc/bind/zones/example.com.zone",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                NSRecord(nsdname="ns1.example.com"),
            ],
        )
    ],
)
view_config = NamedConfig(
    acl_blocks=[
        AclBlock(name="internal", addresses=["192.168.0.0/16", "10.0.0.0/8"]),
        AclBlock(name="external", addresses=["any"]),
    ],
    key_blocks=[
        KeyBlock(name="tsig-key", algorithm="hmac-sha256", secret="aGVsbG8td29ybGQ="),
        KeyBlock(name='"rndc-key"', algorithm="hmac-sha512", secret='"YW5vdGhlci1zZWNyZXQ="'),
    ],
    options_block=OptionsBlock(
        directory="/var/named",
        recursion=True,
        allow_recursion=["internal"],
        dnssec_validation="auto",
        listen_on=["127.0.0.1", IPv4Address("192.168.1.100")],
        listen_on_v6=["::1", IPv6Address("2001:db8::1")],
    ),
    logging_block=LoggingBlock(
        channels=[
            LogChannel(
                name="default",
                file="/var/log/named/default.log",
                severity="info",
                print_category=True,
                print_severity=True,
            )
        ]
    ),
    view_blocks=[
        ViewBlock(
            name="internal-view",
            match_clients=["internal"],
            match_recursive_only=True,
            view_zones=[
                ZoneBlock(
                    name="internal.example.com",
                    zone_type=ZoneTypeEnum.PRIMARY,
                    file="/var/named/internal.zone",
                    allow_query=["internal"],
                    resource_records=[
                        SOARecord(
                            mname="ns.internal.example.com",
                            rname="admin.internal.example.com",
                            serial=2024010101,
                            refresh="3h",
                            retry="1h",
                            expire="1w",
                            minimum="1h",
                        )
                    ],
                )
            ],
        ),
        ViewBlock(
            name="external-view",
            match_clients=["external"],
            match_recursive_only=False,
            view_zones=[
                ZoneBlock(
                    name="example.com",
                    zone_type=ZoneTypeEnum.PRIMARY,
                    file="/var/named/external.zone",
                    allow_query=["any"],
                    resource_records=[
                        SOARecord(
                            mname="ns.example.com",
                            rname="admin.example.com",
                            serial=2024010102,
                            refresh="4h",
                            retry="2h",
                            expire="2w",
                            minimum="2h",
                        )
                    ],
                )
            ],
        ),
    ],
)
full_config = NamedConfig(  # NOTE: GENERATE FILES EXAMPLE
    acl_blocks=[
        AclBlock(
            name="trusted",
            addresses=["192.168.0.0/24", IPv4Network("10.0.0.0/8"), "key admin-key"],
        ),
        AclBlock(name="clients", addresses=["any"]),
    ],
    key_blocks=[
        KeyBlock(name="admin-key", algorithm="hmac-sha256", secret="YWRtaW4ta2V5"),
        KeyBlock(name='"zone-key"', algorithm="hmac-sha1-80", secret='"em9uZS1rZXk="'),
    ],
    key_store_blocks=[
        KeyStoreBlock(name="dnssec-keystore", directory="/etc/bind/keys"),
        KeyStoreBlock(name="hsm-keystore", pkcs11_uri='"pkcs11:token=bind-token"'),
    ],
    tls_blocks=[
        TlsBlock(name="ephemeral"),  # built-in
        TlsBlock(
            name="secure-tls",
            key_file="/etc/ssl/private/named.key",
            cert_file="/etc/ssl/certs/named.crt",
            ca_file="/etc/ssl/certs/ca-bundle.crt",
            protocols=["TLSv1.2", "TLSv1.3"],
            prefer_server_ciphers=True,
            session_tickets="no",
        ),
    ],
    trust_anchors_blocks=[
        TrustAnchorsBlock(
            anchors=[
                KeyTrustAnchor(
                    domain=".",
                    anchor_type=AnchorTypeEnum.INITIAL_KEY,
                    flags=257,
                    protocol=3,
                    algorithm=8,
                    key_data='"AwEAAcFcGsaxxdKkuJ..."',
                )
            ]
        )
    ],
    dnssec_policy_blocks=[
        DnssecPolicyBlock(
            name="secure-policy",
            keys=[
                DnssecKeyEntry(
                    role=KeyRoleEnum.KSK,
                    lifetime=365,
                    algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
                    key_size=256,
                ),
                DnssecKeyEntry(
                    role=KeyRoleEnum.ZSK,
                    lifetime=30,
                    algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
                    key_size=256,
                ),
            ],
        )
    ],
    controls_block=ControlsBlock(
        controls=[
            InetControl(
                ip_address="127.0.0.1",
                port=953,
                allow=["localhost"],
                keys=["rndc-key"],
                read_only=False,
            ),
            InetControl(
                ip_address=IPv6Address("::1"),
                port="*",
                allow=["::1"],
                read_only=False,
            ),
        ]
    ),
    statistics_channels_blocks=[
        StatisticsChannelsBlock(
            channels=[
                InetChannel(address="127.0.0.1", port=8080, allow=["127.0.0.1", "::1"]),
                InetChannel(address="*", port=80, allow=["any"]),
            ]
        )
    ],
    server_blocks=[
        ServerBlock(
            netprefix="192.168.1.0/24", bogus=1, edns="yes", provide_ixfr=False, request_ixfr=0
        ),
        ServerBlock(
            netprefix=IPv4Network("10.0.0.0/8"),
            tcp_only=True,
            request_nsid=1,
            require_cookie="yes",
        ),
    ],
    remote_servers_blocks=[
        RemoteServersBlock(
            name="root-servers",
            port=53,
            source="*",
            source_v6="*",
            servers=[
                RemoteServerEntry(server="198.41.0.4"),
                RemoteServerEntry(server="199.9.14.201", port="5353"),
                RemoteServerEntry(server=IPv6Address("2001:503:ba3e::2:30")),
            ],
        )
    ],
    http_blocks=[
        HttpBlock(
            name="doh",
            endpoints=['"/dns-query"', '"/resolve"'],
            listener_clients=100,
            streams_per_connection=100,
        )
    ],
    options_block=OptionsBlock(
        directory="/var/named",
        pid_file="/var/run/named/named.pid",
        recursion="yes",
        allow_recursion=["trusted"],
        dnssec_validation="auto",
        listen_on=["127.0.0.1", "192.168.1.100"],
        listen_on_v6=["::1", "2001:db8::100"],
        allow_query=["clients"],
        allow_transfer=["secondary-servers"],
        max_cache_size="90%",
        lame_ttl="10m",
        max_cache_ttl="1d",
        min_cache_ttl="1s",
    ),
    logging_block=LoggingBlock(
        channels=[
            LogChannel(
                name="query-log",
                file="/var/log/named/query.log",
                severity="info",
                print_category=True,
                print_severity="yes",
                print_time="iso8601",
            ),
            LogChannel(
                name="error-log", file="/var/log/named/error.log", severity="error", buffered=0
            ),
        ],
        categories=[
            LogCategory(name=LogCategoryEnum.QUERIES, channels=["query-log"]),
            LogCategory(name=LogCategoryEnum.SECURITY, channels=["error-log"]),
        ],
    ),
    zone_blocks=[
        ZoneBlock(
            name="example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/named/zones/example.com.zone",
            allow_query=["any"],
            allow_transfer=["secondary-servers"],
            dnssec_policy="secure-policy",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh=10800,
                    retry=3600,
                    expire=604800,
                    minimum=3600,
                ),
                NSRecord(nsdname="ns1.example.com"),
                NSRecord(nsdname="ns2.example.com"),
                ARecord(name="@", address="192.168.1.1"),
                MXRecord(name="@", preference=10, exchange="mail.example.com"),
                TXTRecord(name="@", text_data=['"v=spf1 mx ~all"']),
            ],
        ),
        ZoneBlock(
            name="2.0.192.in-addr.arpa",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/var/named/zones/reverse.zone",
            resource_records=[
                SOARecord(
                    mname="ns1.example.com",
                    rname="admin.example.com",
                    serial=2024010101,
                    refresh="3h",
                    retry="1h",
                    expire="1w",
                    minimum="1h",
                )
            ],
        ),
    ],
)
print(minimal_config.model_bind_syntax())
# options {
#     allow-recursion {
#         localhost;
#         localnets;
#     };
#     directory "/etc/bind";
#     listen-on {
#         any;
#     };
#     listen-on-v6 {
#         any;
#     };
#     recursion yes;
# };

# zone example.com {
#     type primary;
#     file "/etc/bind/zones/example.com.zone";
# };
print(view_config.model_bind_syntax())
# acl external {
#     any;
# };

# acl internal {
#     10.0.0.0/8;
#     192.168.0.0/16;
# };

# key "rndc-key" {
#     algorithm hmac-sha512;
#     secret "YW5vdGhlci1zZWNyZXQ=";
# };
# key "tsig-key" {
#     algorithm hmac-sha256;
#     secret "aGVsbG8td29ybGQ=";
# };

# options {
#     allow-recursion {
#         internal;
#     };
#     directory "/var/named";
#     dnssec-validation auto;
#     listen-on {
#         127.0.0.1;
#         192.168.1.100;
#     };
#     listen-on-v6 {
#         2001:db8::1;
#         ::1;
#     };
#     recursion yes;
# };

# logging {
#     channel default {
#         file "/var/log/named/default.log";
#         print-category yes;
#         print-severity yes;
#         severity info;
#     };
# };

# view external-view {
#     match-clients {
#         external;
#     };
#     match-recursive-only no;
#     zone example.com {
#         type primary;
#         allow-query {
#             any;
#         };
#         file "/var/named/external.zone";
#     };
# };

# view internal-view {
#     match-clients {
#         internal;
#     };
#     match-recursive-only yes;
#     zone internal.example.com {
#         type primary;
#         allow-query {
#             internal;
#         };
#         file "/var/named/internal.zone";
#     };
# };
print(full_config.model_bind_syntax())
# acl clients {
#     any;
# };

# acl trusted {
#     10.0.0.0/8;
#     192.168.0.0/24;
#     key admin-key;
# };

# key "admin-key" {
#     algorithm hmac-sha256;
#     secret "YWRtaW4ta2V5";
# };
# key "zone-key" {
#     algorithm hmac-sha1-80;
#     secret "em9uZS1rZXk=";
# };

# key-store dnssec-keystore {
#     directory /etc/bind/keys;
# };
# key-store hsm-keystore {
#     pkcs11-uri "pkcs11:token=bind-token";
# };

# tls ephemeral {};
# tls secure-tls {
#     ca-file "/etc/ssl/certs/ca-bundle.crt";
#     cert-file "/etc/ssl/certs/named.crt";
#     key-file "/etc/ssl/private/named.key";
#     prefer-server-ciphers yes;
#     protocols {
#         TLSv1.2;
#         TLSv1.3;
#     };
#     session-tickets no;
# };

# controls {
#     inet 127.0.0.1
#         allow {
#             localhost;
#         }
#         keys {
#             rndc-key;
#         }
#         read-only no
#     ;
#     inet ::1 port *
#         allow {
#             ::1;
#         }
#         read-only no
#     ;
# };

# server 10.0.0.0/8 {
#     request-nsid yes;
#     require-cookie yes;
#     tcp-only yes;
# };
# server 192.168.1.0/24 {
#     bogus yes;
#     edns yes;
#     provide-ixfr no;
#     request-ixfr no;
# };

# trust-anchors {
#     . initial-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
# };

# dnssec-policy secure-policy {
#     keys {
#         ksk lifetime 365 algorithm ecdsap256sha256 256;
#         zsk lifetime 30 algorithm ecdsap256sha256 256;
#     };
# };

# remote-servers root-servers port 53 source * source-v6 * {
#     198.41.0.4;
#     199.9.14.201 port 5353;
#     2001:503:ba3e::2:30;
# };

# http doh {
#     endpoints {
#         "/dns-query";
#         "/resolve";
#     };
#     listener-clients 100;
#     streams-per-connection 100;
# };

# statistics-channels {
#     inet * port 80 allow {
#         any;
#     };
#     inet 127.0.0.1 port 8080 allow {
#         127.0.0.1;
#         ::1;
#     };
# };

# options {
#     allow-query {
#         clients;
#     };
#     allow-recursion {
#         trusted;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     directory "/var/named";
#     dnssec-validation auto;
#     lame-ttl 600;
#     listen-on {
#         127.0.0.1;
#         192.168.1.100;
#     };
#     listen-on-v6 {
#         2001:db8::100;
#         ::1;
#     };
#     max-cache-size 90%;
#     max-cache-ttl 86400;
#     min-cache-ttl 1;
#     pid-file "/var/run/named/named.pid";
#     recursion yes;
# };

# logging {
#     channel error-log {
#         file "/var/log/named/error.log";
#         buffered no;
#         severity error;
#     };
#     channel query-log {
#         file "/var/log/named/query.log";
#         print-category yes;
#         print-severity yes;
#         print-time iso8601;
#         severity info;
#     };
#     category queries {
#         query-log;
#     };
#     category security {
#         error-log;
#     };
# };

# zone 2.0.192.in-addr.arpa {
#     type primary;
#     file "/var/named/zones/reverse.zone";
# };

# zone example.com {
#     type primary;
#     allow-query {
#         any;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     dnssec-policy secure-policy;
#     file "/var/named/zones/example.com.zone";
# };
print(full_config.generate_files())
# [
#     GeneratedFile(
#         path=PosixPath("/var/named/zones/example.com.zone"),
#         content='...',
#         type="zone",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/zones/reverse.zone"),
#         content="...",
#         type="zone",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/keys/tsig-keys.conf"),
#         content='...',
#         type="key",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/keys/key-stores.conf"),
#         content='...',
#         type="key_store",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/dnssec/trust-anchors.conf"),
#         content='...',
#         type="dnssec",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/dnssec/dnssec-policies.conf"),
#         content="...",
#         type="dnssec",
#     ),
#     GeneratedFile(
#         path=PosixPath("/var/named/named.conf"),
#         content='...',
#         type="config",
#     ),
# ]
full_config.write_files(base_dir="./examples/bind_example")
# ./examples/bind_example/dnssec/dnssec-policies.conf
# dnssec-policy secure-policy {
#     keys {
#         ksk lifetime 365 algorithm ecdsap256sha256 256;
#         zsk lifetime 30 algorithm ecdsap256sha256 256;
#     };
# };

# ./examples/bind_example/dnssec/trust-anchors.conf
# trust-anchors {
#     . initial-key 257 3 8 "AwEAAcFcGsaxxdKkuJ...";
# };

# ./examples/bind_example/keys/key-stores.conf
# key-store dnssec-keystore {
#     directory /etc/bind/keys;
# };

# key-store hsm-keystore {
#     pkcs11-uri "pkcs11:token=bind-token";
# };

# ./examples/bind_example/keys/tsig-keys.conf
# key "admin-key" {
#     algorithm hmac-sha256;
#     secret "YWRtaW4ta2V5";
# };

# key "zone-key" {
#     algorithm hmac-sha1-80;
#     secret "em9uZS1rZXk=";
# };

# ./examples/bind_example/zones/example.com.zone
# @                                                IN   SOA ns1.example.com admin.example.com (
#                                                                  2024010101 ; Serial number (YYYYMMDDNN)
#                                                                  10800      ; Refresh time
#                                                                  3600       ; Retry time
#                                                                  604800     ; Expire time
#                                                                  3600       ; Minimum TTL
#                                                       )
# @                                                IN   NS         ns1.example.com
# @                                                IN   NS         ns2.example.com
# @                                                IN   MX         10 mail.example.com
# @                                                IN   A          192.168.1.1
# @                                                IN   TXT        "v=spf1 mx ~all"

# ./examples/bind_example/zones/reverse.zone
# @                                                IN   SOA ns1.example.com. admin.example.com. (
#                                                                  2024010101 ; Serial number (YYYYMMDDNN)
#                                                                  10800      ; Refresh time
#                                                                  3600       ; Retry time
#                                                                  604800     ; Expire time
#                                                                  3600       ; Minimum TTL
#                                                       )

# ./examples/bind_example/named.conf
# # Automatically generated by bindantic - please adjust!

# include "keys/tsig-keys.conf";
# include "keys/key-stores.conf";

# include "dnssec/trust-anchors.conf";
# include "dnssec/dnssec-policies.conf";

# acl clients {
#     any;
# };

# acl trusted {
#     10.0.0.0/8;
#     192.168.0.0/24;
#     key admin-key;
# };

# tls ephemeral {};
# tls secure-tls {
#     ca-file "/etc/ssl/certs/ca-bundle.crt";
#     cert-file "/etc/ssl/certs/named.crt";
#     key-file "/etc/ssl/private/named.key";
#     prefer-server-ciphers yes;
#     protocols {
#         TLSv1.2;
#         TLSv1.3;
#     };
#     session-tickets no;
# };

# controls {
#     inet 127.0.0.1
#         allow {
#             localhost;
#         }
#         keys {
#             rndc-key;
#         }
#         read-only no
#     ;
#     inet ::1 port *
#         allow {
#             ::1;
#         }
#         read-only no
#     ;
# };

# server 10.0.0.0/8 {
#     request-nsid yes;
#     require-cookie yes;
#     tcp-only yes;
# };
# server 192.168.1.0/24 {
#     bogus yes;
#     edns yes;
#     provide-ixfr no;
#     request-ixfr no;
# };

# remote-servers root-servers port 53 source * source-v6 * {
#     198.41.0.4;
#     199.9.14.201 port 5353;
#     2001:503:ba3e::2:30;
# };

# http doh {
#     endpoints {
#         "/dns-query";
#         "/resolve";
#     };
#     listener-clients 100;
#     streams-per-connection 100;
# };

# statistics-channels {
#     inet * port 80 allow {
#         any;
#     };
#     inet 127.0.0.1 port 8080 allow {
#         127.0.0.1;
#         ::1;
#     };
# };

# options {
#     allow-query {
#         clients;
#     };
#     allow-recursion {
#         trusted;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     directory "bind";
#     dnssec-validation auto;
#     lame-ttl 600;
#     listen-on {
#         127.0.0.1;
#         192.168.1.100;
#     };
#     listen-on-v6 {
#         2001:db8::100;
#         ::1;
#     };
#     max-cache-size 90%;
#     max-cache-ttl 86400;
#     min-cache-ttl 1;
#     pid-file "/var/run/named/named.pid";
#     recursion yes;
# };

# logging {
#     channel error-log {
#         file "/var/log/named/error.log";
#         buffered no;
#         severity error;
#     };
#     channel query-log {
#         file "/var/log/named/query.log";
#         print-category yes;
#         print-severity yes;
#         print-time iso8601;
#         severity info;
#     };
#     category queries {
#         query-log;
#     };
#     category security {
#         error-log;
#     };
# };

# zone 2.0.192.in-addr.arpa {
#     type primary;
#     file "zones/reverse.zone";
# };

# zone example.com {
#     type primary;
#     allow-query {
#         any;
#     };
#     allow-transfer {
#         secondary-servers;
#     };
#     dnssec-policy secure-policy;
#     file "zones/example.com.zone";
# };
