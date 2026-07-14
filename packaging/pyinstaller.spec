# PyInstaller spec: one-file connect binary with bundled skill assets.
# Build:  uv run pyinstaller packaging/pyinstaller.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, copy_metadata

repo_root = Path(SPECPATH).parent

# The Ethereum stack (pulled in via mech-client -> aea-ledger-ethereum)
# resolves package versions from installed metadata at import time; the
# frozen app must carry that metadata.
_METADATA_PKGS = [
    "eth-bloom",
    "trie",
    "eth-hash",
    "eth-keys",
    "eth-keyfile",
    "eth-utils",
    "eth-abi",
    "eth-typing",
    "eth-rlp",
    "rlp",
    "hexbytes",
    "py-ecc",
    "py-evm",
    "sortedcontainers",
    # aea discovers ledger plugins through entry points in these packages'
    # metadata
    "open-aea",
    "open-aea-ledger-ethereum",
    "open-aea-ledger-cosmos",
]
_metadata = []
for _pkg in _METADATA_PKGS:
    try:
        _metadata += copy_metadata(_pkg)
    except Exception as _e:
        # expected only for platform-specific packages; a typoed name or a
        # broken install would otherwise skip silently and fail at runtime
        print(f"pyinstaller.spec: skipping metadata for {_pkg}: {_e}")

a = Analysis(
    [str(repo_root / "connect" / "__main__.py")],
    pathex=[str(repo_root)],
    datas=[(str(repo_root / "connect" / "assets"), "assets")]
    # mech-client loads mechs.json, contract ABIs and templates at runtime;
    # safe-eth-py loads Safe contract ABIs the same way
    + collect_data_files("mech_client")
    + collect_data_files("safe_eth")
    # open-aea loads its configuration schemas at import
    + collect_data_files("aea")
    + collect_data_files("aea_ledger_ethereum")
    # operate embeds aea contract packages whose fingerprint check hashes
    # every file, including the .py ones
    + collect_data_files("operate", include_py_files=True)
    + _metadata,
    hiddenimports=[
        "eth_account",
        "web3",
        "aea_ledger_ethereum",
        "aea_ledger_cosmos",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    # aea resolves its schema dir via inspect.getfile(currentframe()), which
    # inside the PYZ archive yields a relative path — ship it as source files.
    module_collection_mode={"aea": "py"},
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="connect",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=True,
)
