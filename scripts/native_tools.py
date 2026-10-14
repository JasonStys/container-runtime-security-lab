"""Jason Stys: official digest-pinned Falco and k8saudit native tooling, extracted as allowlisted regular files only."""
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# variable: ROOT — line 42
# variable: CAP — line 43
# definition: download — line 46
# parameter: digest — line 46
# parameter: headers — line 46
# parameter: url — line 46
# variable: response — line 48
# variable: data — line 49
# definition: member — line 57
# parameter: data — line 57
# parameter: name — line 57
# parameter: output — line 57
# variable: archive — line 59
# variable: item — line 60
# variable: stream — line 63
# variable: target — line 66
# definition: main — line 71
# variable: lock — line 73
# variable: output — line 74
# variable: falco — line 76
# variable: archive — line 82
# variable: prefix — line 83
# variable: plugin — line 90
# variable: repository — line 91
# variable: response — line 100
# variable: token — line 101
# variable: headers — line 102
# variable: base — line 106
# variable: manifest — line 107
# variable: archive — line 115
# END CODE MAP

import hashlib
import io
import json
import tarfile
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CAP = 96 * 1024 * 1024


def download(url: str, digest: str, headers: dict[str, str] | None = None) -> bytes:
    """Bound a vendor HTTPS download and verify SHA256 before parsing or loading its contents."""
    with urlopen(Request(url, headers=headers or {}), timeout=60) as response:
        data = response.read(CAP + 1)
    if len(data) > CAP or hashlib.sha256(data).hexdigest() != digest.removeprefix(
        "sha256:"
    ):
        raise ValueError("native tool digest mismatch or size cap")
    return data


def member(data: bytes, name: str, output: Path) -> None:
    """Copy one exact bounded regular tar member; never extract archive paths, links, scripts or credentials."""
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        item = archive.getmember(name)
        if not item.isfile() or item.size > CAP:
            raise ValueError("native member must be a bounded regular file")
        stream = archive.extractfile(item)
        if stream is None:
            raise ValueError("native tool missing")
        with stream, output.open("xb") as target:
            target.write(stream.read(CAP + 1))
    output.chmod(0o700)


def main() -> None:
    """Install reviewed Falco 0.45.0 and k8saudit 0.18.0 into ignored repo-local .tools; no host install/driver changes."""
    lock = json.loads((ROOT / "tools.lock.json").read_text())
    output = ROOT / ".tools"
    output.mkdir(exist_ok=True, mode=0o700)
    falco = lock["falco"]
    if (
        falco["url"]
        != "https://download.falco.org/packages/bin/x86_64/falco-0.45.0-x86_64.tar.gz"
    ):
        raise ValueError("Falco must use the reviewed official artifact")
    archive = download(falco["url"], falco["sha256"])
    prefix = "falco-0.45.0-x86_64/"
    member(archive, prefix + "usr/bin/falco", output / "falco")
    member(
        archive,
        prefix + "usr/share/falco/plugins/libcontainer.so",
        output / "libcontainer.so",
    )
    plugin = lock["k8saudit"]
    repository = "falcosecurity/plugins/plugin/k8saudit"
    if plugin["repository"] != repository:
        raise ValueError("plugin must use reviewed official repository")
    # Anonymous registry token is pull-only; never log it or request account credentials.
    with urlopen(
        "https://ghcr.io/token?service=ghcr.io&scope=repository:"
        + repository
        + ":pull",
        timeout=30,
    ) as response:
        token = json.load(response)["token"]
    headers = {
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.oci.image.manifest.v1+json",
    }
    base = "https://ghcr.io/v2/" + repository + "/"
    manifest = json.loads(
        download(base + "manifests/" + plugin["manifest"], plugin["manifest"], headers)
    )
    if (
        len(manifest["layers"]) != 1
        or manifest["layers"][0]["digest"] != plugin["layer"]
    ):
        raise ValueError("unexpected plugin OCI layer")
    archive = download(base + "blobs/" + plugin["layer"], plugin["layer"], headers)
    member(archive, "libk8saudit.so", output / "libk8saudit.so")
    print(
        "Official Falco/plugin digests verified; native binaries were not executed by the installer."
    )


if __name__ == "__main__":
    main()
