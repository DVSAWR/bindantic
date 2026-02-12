from __future__ import annotations

from pathlib import Path
from unittest.mock import mock_open, patch

import pytest

from bindantic import (
    AclBlock,
    AnchorTypeEnum,
    ARecord,
    ControlsBlock,
    DnssecAlgorithmEnum,
    DnssecKeyEntry,
    DnssecPolicyBlock,
    HttpBlock,
    InetChannel,
    InetControl,
    KeyBlock,
    KeyRoleEnum,
    KeyStoreBlock,
    KeyTrustAnchor,
    LogChannel,
    LoggingBlock,
    NamedConfig,
    OptionsBlock,
    RemoteServerEntry,
    RemoteServersBlock,
    ServerBlock,
    StatisticsChannelsBlock,
    TlsBlock,
    TrustAnchorsBlock,
    ViewBlock,
    ZoneBlock,
    ZoneTypeEnum,
)
from bindantic.named_config import GeneratedFile

# Fixtures - minimal reusable building blocks


@pytest.fixture
def acl_block_a() -> AclBlock:
    return AclBlock(name="alpha", addresses=["192.168.1.0/24"])


@pytest.fixture
def acl_block_b() -> AclBlock:
    return AclBlock(name="beta", addresses=["10.0.0.0/8"])


@pytest.fixture
def key_block_a() -> KeyBlock:
    return KeyBlock(name="key-a", algorithm="hmac-sha256", secret="AAAA")


@pytest.fixture
def key_block_b() -> KeyBlock:
    return KeyBlock(name="key-b", algorithm="hmac-sha512", secret="BBBB")


@pytest.fixture
def key_store_block() -> KeyStoreBlock:
    return KeyStoreBlock(name="keystore", directory="/etc/bind/keys")


@pytest.fixture
def tls_block() -> TlsBlock:
    return TlsBlock(name="tls-profile", key_file="key.pem", cert_file="cert.pem")


@pytest.fixture
def trust_anchor() -> TrustAnchorsBlock:
    return TrustAnchorsBlock(
        anchors=[
            KeyTrustAnchor(
                domain=".",
                anchor_type=AnchorTypeEnum.INITIAL_KEY,
                flags=257,
                protocol=3,
                algorithm=8,
                key_data='"keydata"',
            )
        ]
    )


@pytest.fixture
def dnssec_policy() -> DnssecPolicyBlock:
    return DnssecPolicyBlock(
        name="policy",
        keys=[
            DnssecKeyEntry(
                role=KeyRoleEnum.ZSK,
                lifetime="30d",
                algorithm=DnssecAlgorithmEnum.ECDSAP256SHA256,
            )
        ],
    )


@pytest.fixture
def remote_servers_block() -> RemoteServersBlock:
    return RemoteServersBlock(
        name="root-servers",
        servers=[RemoteServerEntry(server="198.41.0.4")],
    )


@pytest.fixture
def http_block() -> HttpBlock:
    return HttpBlock(name="doh", endpoints=["/dns-query"])


@pytest.fixture
def stats_channel_block() -> StatisticsChannelsBlock:
    """Use InetChannel with correct field name 'address'."""
    return StatisticsChannelsBlock(
        channels=[InetChannel(address="127.0.0.1", port=8080, allow=["localhost"])]
    )


@pytest.fixture
def server_block() -> ServerBlock:
    return ServerBlock(netprefix="192.168.1.0/24", bogus=True)


@pytest.fixture
def primary_zone() -> ZoneBlock:
    return ZoneBlock(
        name="example.com",
        zone_type=ZoneTypeEnum.PRIMARY,
        file="/etc/bind/zones/example.com.zone",
        resource_records=[
            ARecord(name="@", address="192.168.1.1"),
        ],
    )


@pytest.fixture
def secondary_zone() -> ZoneBlock:
    return ZoneBlock(
        name="example.net",
        zone_type=ZoneTypeEnum.SECONDARY,
        primaries=["192.168.1.2"],
    )


@pytest.fixture
def view_with_zones() -> ViewBlock:
    return ViewBlock(
        name="internal",
        match_clients=["localhost"],
        view_zones=[
            ZoneBlock(
                name="internal.example.com",
                zone_type=ZoneTypeEnum.PRIMARY,
                file="/etc/bind/zones/internal.zone",
                resource_records=[ARecord(name="@", address="10.0.0.1")],
            )
        ],
    )


@pytest.fixture
def minimal_options() -> OptionsBlock:
    return OptionsBlock(directory="/var/named", recursion=True)


class TestNamedConfigModelBindSyntax:
    """BIND syntax generation tests."""

    def test_empty_config(self):
        """Empty configuration → empty string (no trailing newlines)."""
        cfg = NamedConfig()
        assert cfg.model_bind_syntax() == ""

    def test_only_acl_blocks_sorted(self, acl_block_b, acl_block_a):
        """ACL blocks are sorted by name and separated by a blank line."""
        cfg = NamedConfig(acl_blocks=[acl_block_b, acl_block_a])
        syntax = cfg.model_bind_syntax()

        assert "};\n\nacl beta" in syntax

    def test_key_and_tls_blocks_ordering(self, key_block_b, key_block_a, tls_block):
        """key-blocks, key-store-blocks, tls-blocks appear in correct order,
        each group separated by a blank line."""
        cfg = NamedConfig(
            key_blocks=[key_block_b, key_block_a],
            key_store_blocks=[KeyStoreBlock(name="store", directory="/tmp")],
            tls_blocks=[tls_block],
        )
        syntax = cfg.model_bind_syntax()

        assert syntax.index('key "key-a"') < syntax.index("key-store store")
        assert syntax.index("key-store store") < syntax.index("tls tls-profile")

        assert "};\n\nkey-store" in syntax
        assert "};\n\ntls" in syntax

    def test_controls_block(self):
        """Controls block is printed, no trailing blank line when alone."""
        ctrl = ControlsBlock(controls=[InetControl(ip_address="127.0.0.1", allow=["localhost"])])
        cfg = NamedConfig(controls_block=ctrl)
        syntax = cfg.model_bind_syntax()

        assert syntax.startswith("controls {")
        assert syntax.endswith("};")

    def test_server_blocks_sorted(self, server_block):
        """Server blocks are sorted and separated by a single newline."""
        srv2 = ServerBlock(netprefix="10.0.0.0/8", bogus=False)
        cfg = NamedConfig(server_blocks=[srv2, server_block])
        syntax = cfg.model_bind_syntax()

        assert syntax.index("server 10.0.0.0/8") < syntax.index("server 192.168.1.0/24")

        assert "};\nserver" in syntax

    def test_trust_anchors_and_dnssec_policy(self, trust_anchor, dnssec_policy):
        """Trust-anchors and dnssec-policy appear in the order they were added,
        separated by a blank line."""
        cfg = NamedConfig(
            trust_anchors_blocks=[trust_anchor],
            dnssec_policy_blocks=[dnssec_policy],
        )
        syntax = cfg.model_bind_syntax()

        assert syntax.index("trust-anchors") < syntax.index("dnssec-policy policy")

        assert "};\n\ndnssec-policy" in syntax

    def test_remote_servers_http_stats_sorted(
        self, remote_servers_block, http_block, stats_channel_block
    ):
        """remote-servers, http, statistics-channels are sorted and separated."""
        rs2 = RemoteServersBlock(name="a-servers", servers=[RemoteServerEntry(server="1.1.1.1")])
        cfg = NamedConfig(
            remote_servers_blocks=[remote_servers_block, rs2],
            http_blocks=[http_block],
            statistics_channels_blocks=[stats_channel_block],
        )
        syntax = cfg.model_bind_syntax()

        assert syntax.index("remote-servers a-servers") < syntax.index(
            "remote-servers root-servers"
        )

        idx_rs = syntax.index("remote-servers")
        idx_http = syntax.index("http")
        idx_stats = syntax.index("statistics-channels")
        assert idx_rs < idx_http < idx_stats

    def test_options_and_logging(self, minimal_options):
        """Options and Logging blocks are printed and separated."""
        log = LoggingBlock(channels=[LogChannel(name="default", file="/dev/null")])
        cfg = NamedConfig(options_block=minimal_options, logging_block=log)
        syntax = cfg.model_bind_syntax()
        assert syntax.startswith("options {")
        assert "logging {" in syntax
        assert "};\n\nlogging" in syntax or "\nlogging" in syntax

    def test_views_without_zones(self, view_with_zones):
        """If view_blocks exist, top-level zone_blocks are omitted."""
        zone = ZoneBlock(name="orphan", zone_type=ZoneTypeEnum.PRIMARY, file="/dev/null")
        cfg = NamedConfig(view_blocks=[view_with_zones], zone_blocks=[zone])
        syntax = cfg.model_bind_syntax()
        assert "zone orphan" not in syntax
        assert "view internal" in syntax
        assert "zone internal.example.com" in syntax

    def test_only_zone_blocks_when_no_views(self, primary_zone, secondary_zone):
        """Without view_blocks - zones are printed and sorted."""
        cfg = NamedConfig(zone_blocks=[secondary_zone, primary_zone])
        syntax = cfg.model_bind_syntax()

        assert syntax.index("zone example.com") < syntax.index("zone example.net")
        assert not syntax.endswith("\n\n")


class TestGetDirectories:
    """Target directory resolution tests."""

    def test_default_directories(self, tmp_path):
        """Without options_block - standard subdirectories inside base_path."""
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        assert dirs["base"] == tmp_path
        assert dirs["zones"] == tmp_path / "zones"
        assert dirs["keys"] == tmp_path / "keys"
        assert dirs["dnssec"] == tmp_path / "dnssec"

    def test_with_key_directory_relative(self, tmp_path):
        """key_directory relative path."""
        opts = OptionsBlock(key_directory="custom-keys")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        assert dirs["keys"] == tmp_path / "custom-keys"

    def test_with_key_directory_absolute(self, tmp_path):
        """key_directory absolute path - take only the last component."""
        opts = OptionsBlock(key_directory="/etc/bind/keys")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        assert dirs["keys"] == tmp_path / "keys"

    def test_with_managed_keys_directory_relative(self, tmp_path):
        """managed_keys_directory relative path."""
        opts = OptionsBlock(managed_keys_directory="dnssec-keys")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        assert dirs["dnssec"] == tmp_path / "dnssec-keys"

    def test_with_managed_keys_directory_absolute(self, tmp_path):
        """managed_keys_directory absolute path."""
        opts = OptionsBlock(managed_keys_directory="/var/named/managed")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        assert dirs["dnssec"] == tmp_path / "managed"


class TestGenerateZoneFiles:
    """Zone file generation tests."""

    def test_no_zones(self, tmp_path):
        """No zones → empty list."""
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert files == []

    def test_primary_zone_with_file_and_rr(self, tmp_path, primary_zone):
        """Primary zone with explicit file and resource records."""
        cfg = NamedConfig(zone_blocks=[primary_zone])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert len(files) == 1
        gf = files[0]
        assert gf.type == "zone"
        expected_path = tmp_path / "zones" / "example.com.zone"
        assert gf.path == expected_path
        assert gf.content.startswith("@")

        assert primary_zone.file == '"zones/example.com.zone"'

    def test_primary_zone_without_file(self, tmp_path):
        """Primary zone without file - name generated from domain."""
        zone = ZoneBlock(
            name="sub.example.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            resource_records=[ARecord(name="@", address="10.0.0.1")],
        )
        cfg = NamedConfig(zone_blocks=[zone])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert len(files) == 1
        assert files[0].path == tmp_path / "zones" / "sub_example_com.zone"
        assert zone.file == '"zones/sub_example_com.zone"'

    def test_primary_zone_without_rr(self, tmp_path):
        """Primary zone without resource_records - file is not generated."""
        zone = ZoneBlock(
            name="empty.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/dev/null",
        )
        cfg = NamedConfig(zone_blocks=[zone])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert files == []

    def test_secondary_zone_ignored(self, tmp_path, secondary_zone):
        """Secondary zone does not generate a file (even with RRs)."""
        secondary_zone.resource_records = [ARecord(name="@", address="1.1.1.1")]
        cfg = NamedConfig(zone_blocks=[secondary_zone])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert files == []

    def test_zone_file_already_absolute(self, tmp_path):
        """If file is absolute, only the filename is used in the resulting path."""
        zone = ZoneBlock(
            name="test.com",
            zone_type=ZoneTypeEnum.PRIMARY,
            file="/etc/bind/pri/test.com.zone",
            resource_records=[ARecord(name="@", address="1.1.1.1")],
        )
        cfg = NamedConfig(zone_blocks=[zone])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert files[0].path == tmp_path / "zones" / "test.com.zone"
        assert zone.file == '"zones/test.com.zone"'

    def test_zones_from_views(self, tmp_path, view_with_zones):
        """Zones inside view_blocks are processed, zone_blocks are ignored."""
        cfg = NamedConfig(
            view_blocks=[view_with_zones],
            zone_blocks=[ZoneBlock(name="orphan", zone_type=ZoneTypeEnum.PRIMARY)],
        )
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert len(files) == 1
        assert "internal.zone" in str(files[0].path)

    def test_duplicate_zones(self, tmp_path):
        """Identical zone names (e.g. from different views) are processed only once."""
        view1 = ViewBlock(
            name="v1",
            view_zones=[
                ZoneBlock(
                    name="shared.com",
                    zone_type=ZoneTypeEnum.PRIMARY,
                    resource_records=[ARecord(name="@", address="1.1.1.1")],
                )
            ],
        )
        view2 = ViewBlock(
            name="v2",
            view_zones=[
                ZoneBlock(
                    name="shared.com",
                    zone_type=ZoneTypeEnum.PRIMARY,
                    resource_records=[ARecord(name="@", address="2.2.2.2")],
                )
            ],
        )
        cfg = NamedConfig(view_blocks=[view1, view2])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_zone_files(dirs)
        assert len(files) == 1


class TestGenerateKeyFiles:
    """Key file generation tests."""

    def test_no_keys(self, tmp_path):
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_key_files(dirs)
        assert files == []

    def test_key_blocks(self, tmp_path, key_block_a, key_block_b):
        cfg = NamedConfig(key_blocks=[key_block_b, key_block_a])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_key_files(dirs)
        assert len(files) == 1
        gf = files[0]
        assert gf.type == "key"
        assert gf.path == dirs["keys"] / "tsig-keys.conf"

        assert gf.content.index('key "key-a"') < gf.content.index('key "key-b"')
        assert not gf.content.endswith("\n\n")

    def test_key_store_blocks(self, tmp_path, key_store_block):
        cfg = NamedConfig(key_store_blocks=[key_store_block])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_key_files(dirs)
        assert len(files) == 1
        assert files[0].type == "key_store"
        assert files[0].path == dirs["keys"] / "key-stores.conf"
        assert "key-store keystore" in files[0].content

    def test_both_key_and_store(self, tmp_path, key_block_a, key_store_block):
        cfg = NamedConfig(key_blocks=[key_block_a], key_store_blocks=[key_store_block])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_key_files(dirs)
        assert len(files) == 2
        assert files[0].type == "key"
        assert files[1].type == "key_store"


class TestGenerateDnssecFiles:
    """DNSSEC file generation (trust-anchors, policies) tests."""

    def test_no_dnssec_blocks(self, tmp_path):
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_dnssec_files(dirs)
        assert files == []

    def test_trust_anchors(self, tmp_path, trust_anchor):
        cfg = NamedConfig(trust_anchors_blocks=[trust_anchor])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_dnssec_files(dirs)
        assert len(files) == 1
        gf = files[0]
        assert gf.type == "dnssec"
        assert gf.path == dirs["dnssec"] / "trust-anchors.conf"
        assert "trust-anchors {" in gf.content

    def test_dnssec_policies(self, tmp_path, dnssec_policy):
        cfg = NamedConfig(dnssec_policy_blocks=[dnssec_policy])
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_dnssec_files(dirs)
        assert len(files) == 1
        assert "dnssec-policy policy" in files[0].content

    def test_both_trust_and_policy(self, tmp_path, trust_anchor, dnssec_policy):
        cfg = NamedConfig(
            trust_anchors_blocks=[trust_anchor],
            dnssec_policy_blocks=[dnssec_policy],
        )
        dirs = cfg._get_directories(tmp_path)
        files = cfg._generate_dnssec_files(dirs)
        assert len(files) == 2

        assert files[0].path.name == "trust-anchors.conf"
        assert files[1].path.name == "dnssec-policies.conf"


class TestGenerateMainConfig:
    """Main named.conf generation tests."""

    def test_minimal_main_config(self, tmp_path, minimal_options):
        """Minimal config without includes."""
        cfg = NamedConfig(options_block=minimal_options)
        dirs = cfg._get_directories(tmp_path)
        main_cfg = cfg._generate_main_config(dirs, [], [], [])
        assert main_cfg.type == "config"
        assert main_cfg.path == dirs["base"] / "named.conf"
        assert main_cfg.content.startswith("# Automatically generated by bindantic")
        assert f'directory "{dirs["base"]}";' in main_cfg.content

    def test_includes_generated(self, tmp_path):
        """Check that include directives are added for generated files."""
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        zone_file = GeneratedFile(path=dirs["zones"] / "example.zone", content="", type="zone")
        key_file = GeneratedFile(path=dirs["keys"] / "tsig-keys.conf", content="", type="key")
        dnssec_file = GeneratedFile(
            path=dirs["dnssec"] / "trust-anchors.conf", content="", type="dnssec"
        )
        main_cfg = cfg._generate_main_config(
            dirs,
            zone_files=[zone_file],
            key_files=[key_file],
            dnssec_files=[dnssec_file],
        )
        content = main_cfg.content
        assert 'include "keys/tsig-keys.conf";' in content
        assert 'include "dnssec/trust-anchors.conf";' in content

        assert "zones/example.zone" not in content

    def test_include_absolute_path_fallback(self, tmp_path):
        """If relative path cannot be computed, absolute path is used."""
        cfg = NamedConfig()
        dirs = cfg._get_directories(tmp_path)
        abs_key_file = GeneratedFile(path=Path("/etc/bind/keys/tsig.conf"), content="", type="key")
        main_cfg = cfg._generate_main_config(dirs, [], [abs_key_file], [])
        assert 'include "/etc/bind/keys/tsig.conf";' in main_cfg.content

    def test_options_directory_updated(self, tmp_path, minimal_options):
        """options_block.directory is forcibly replaced with base_dir."""
        cfg = NamedConfig(options_block=minimal_options)
        dirs = cfg._get_directories(tmp_path)
        main_cfg = cfg._generate_main_config(dirs, [], [], [])
        assert f'directory "{dirs["base"]}";' in main_cfg.content

    def test_key_directory_adjusted(self, tmp_path):
        """Absolute key_directory is reduced to its directory name."""
        opts = OptionsBlock(key_directory="/var/named/keys")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        main_cfg = cfg._generate_main_config(dirs, [], [], [])
        assert 'key-directory "keys";' in main_cfg.content

    def test_managed_keys_directory_adjusted(self, tmp_path):
        """Absolute managed_keys_directory is reduced to its directory name."""
        opts = OptionsBlock(managed_keys_directory="/var/named/managed")
        cfg = NamedConfig(options_block=opts)
        dirs = cfg._get_directories(tmp_path)
        main_cfg = cfg._generate_main_config(dirs, [], [], [])
        assert 'managed-keys-directory "managed";' in main_cfg.content

    def test_blocks_cleared_in_copy(self, key_block_a, trust_anchor, dnssec_policy):
        """In the main config, key_blocks, key_store_blocks and DNSSEC blocks are cleared."""
        cfg = NamedConfig(
            key_blocks=[key_block_a],
            key_store_blocks=[KeyStoreBlock(name="store", directory="/tmp")],
            trust_anchors_blocks=[trust_anchor],
            dnssec_policy_blocks=[dnssec_policy],
            options_block=OptionsBlock(directory="/tmp"),
        )
        dirs = cfg._get_directories(Path("/fake"))
        main_cfg = cfg._generate_main_config(dirs, [], [], [])

        assert 'key "key-a"' not in main_cfg.content
        assert "key-store store" not in main_cfg.content
        assert "trust-anchors" not in main_cfg.content
        assert "dnssec-policy" not in main_cfg.content


class TestGenerateFiles:
    """Integration tests for full file generation."""

    def test_generate_files_no_base_dir(self, tmp_path, monkeypatch):
        """If base_dir is not given, directory from options_block is used (absolute)."""
        monkeypatch.chdir(tmp_path)
        opts = OptionsBlock(directory="/var/named")
        cfg = NamedConfig(options_block=opts)
        files = cfg.generate_files()

        assert files[-1].path == Path("/var/named") / "named.conf"

    def test_generate_files_with_base_dir(self, tmp_path, primary_zone):
        """Explicit base_dir overrides everything."""
        cfg = NamedConfig(zone_blocks=[primary_zone])
        files = cfg.generate_files(base_dir=str(tmp_path))
        for f in files:
            assert str(f.path).startswith(str(tmp_path))

    def test_full_generation_flow(self, tmp_path, acl_block_a, key_block_a, primary_zone):
        """Full cycle: generate_files returns all expected files."""
        cfg = NamedConfig(
            acl_blocks=[acl_block_a],
            key_blocks=[key_block_a],
            zone_blocks=[primary_zone],
            options_block=OptionsBlock(directory=str(tmp_path)),
        )
        files = cfg.generate_files()

        assert len(files) == 3
        types = {f.type for f in files}
        assert types == {"zone", "key", "config"}

    @patch("pathlib.Path.mkdir")
    @patch("builtins.open", new_callable=mock_open)
    def test_write_files(self, mock_file, mock_mkdir, tmp_path):
        """write_files creates directories and writes files."""
        cfg = NamedConfig()
        test_files = [GeneratedFile(path=tmp_path / "test.conf", content="test", type="config")]

        with patch.object(NamedConfig, "generate_files", return_value=test_files):
            result = cfg.write_files()
        mock_mkdir.assert_called_once_with(parents=True, exist_ok=True)
        mock_file.assert_called_once_with(tmp_path / "test.conf", "w", encoding="utf-8")
        mock_file().write.assert_called_once_with("test")
        assert result == test_files


class TestGeneratedFile:
    """Dataclass for generated files."""

    def test_attributes(self):
        gf = GeneratedFile(path=Path("/a/b/c"), content="data", type="zone")
        assert gf.path == Path("/a/b/c")
        assert gf.content == "data"
        assert gf.type == "zone"

    def test_mutable(self):
        """Dataclass is not frozen, attributes can be changed."""
        gf = GeneratedFile(path=Path("/a"), content="c", type="t")
        gf.path = Path("/b")
        assert gf.path == Path("/b")
