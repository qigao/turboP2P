"""Restore current SDKs; never configure/build CMake or select an older package."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

PACKAGES = {
    "Salts.Native": ("SALTS_ROOT", "lib/cmake/Salts/SaltsConfig.cmake"),
    "SaltsUtils.Native": ("SALTS_UTILS_ROOT", "lib/cmake/SaltsUtils/SaltsUtilsConfig.cmake"),
    "CHttp.Native": ("CHTTP_ROOT", "lib/cmake/Chttp/ChttpConfig.cmake"),
}
RIDS = ("linux-x64", "windows-x64")


def resolve_sdks(assets: dict, packages: Path, rid: str) -> dict[str, tuple[Path, str]]:
    """Use only the exact package/version selected by this restore's assets file."""
    if rid not in RIDS:
        raise ValueError(f"unsupported SDK RID: {rid}")
    package_root = packages.resolve()
    result = {}
    for name, (variable, config) in PACKAGES.items():
        matches = [(key, value) for key, value in assets.get("libraries", {}).items()
                   if key.split("/", 1)[0].casefold() == name.casefold()
                   and value.get("type") == "package"]
        if len(matches) != 1:
            raise ValueError(f"expected exactly one restored {name}, found {len(matches)}")
        identity, metadata = matches[0]
        parts = identity.split("/")
        if len(parts) != 2 or not parts[1]:
            raise ValueError(f"invalid restored package identity: {identity}")
        relative = metadata.get("path")
        if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
            raise ValueError(f"missing/invalid package path for {identity}")
        root = (package_root / relative / "sdk" / rid).resolve()
        if not root.is_relative_to(package_root):
            raise ValueError(f"package path escapes restore directory: {identity}")
        if not (root / config).is_file():
            raise ValueError(f"{identity} is missing {rid}/{config}")
        result[variable] = (root, parts[1])
    return result


def write_lines(path: Path, values: list[str]) -> None:
    if any("\n" in value or "\r" in value for value in values):
        raise ValueError("newline in workflow environment value")
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write("\n".join(values) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rid", required=True, choices=RIDS)
    args = parser.parse_args()
    required = ("GITHUB_TOKEN", "GITHUB_ENV", "GITHUB_PATH", "RUNNER_TEMP", "GITHUB_WORKSPACE",
                "QIGAO_VCPKG_TOOLCHAIN_FILE", "VCPKG_TARGET_TRIPLET")
    for variable in required:
        if not os.environ.get(variable):
            raise ValueError(f"required environment variable is missing: {variable}")
    if not Path(os.environ["QIGAO_VCPKG_TOOLCHAIN_FILE"]).is_file():
        raise ValueError("canonical vcpkg toolchain is missing")
    if os.environ.get("VCPKG_NUGET_REPOSITORY") != "https://github.com/qigao/vcpkg-cache":
        raise ValueError("canonical vcpkg cache repository is not configured")
    if "nugetconfig," not in os.environ.get("VCPKG_BINARY_SOURCES", ""):
        raise ValueError("canonical vcpkg NuGet binary source is not configured")

    # Unique directory prevents stale packages/assets from influencing a new restore.
    work = Path(tempfile.mkdtemp(prefix="turbop2p-sdk-", dir=os.environ["RUNNER_TEMP"]))
    packages = work / "packages"
    config = ET.Element("configuration")
    sources = ET.SubElement(config, "packageSources")
    ET.SubElement(sources, "clear")
    ET.SubElement(sources, "add", key="github", value="https://nuget.pkg.github.com/qigao/index.json")
    config_path = work / "NuGet.Config"
    ET.ElementTree(config).write(config_path, encoding="utf-8", xml_declaration=True)
    project = ET.Element("Project", Sdk="Microsoft.NET.Sdk")
    properties = ET.SubElement(project, "PropertyGroup")
    ET.SubElement(properties, "TargetFramework").text = "net8.0"
    ET.SubElement(properties, "RestorePackagesWithLockFile").text = "false"
    references = ET.SubElement(project, "ItemGroup")
    for name in PACKAGES:
        ET.SubElement(references, "PackageReference", Include=name, Version="*")
    project_path = work / "native-sdks.csproj"
    ET.ElementTree(project).write(project_path, encoding="utf-8", xml_declaration=True)
    child_env = os.environ.copy()
    # Credentials never appear in a file, command argument, or workflow output.
    child_env["NuGetPackageSourceCredentials_github"] = (
        "Username=qigao;Password=" + os.environ["GITHUB_TOKEN"] + ";ValidAuthenticationTypes=Basic")
    subprocess.run(["dotnet", "restore", str(project_path), "--packages", str(packages),
                    "--configfile", str(config_path), "--no-cache", "--force-evaluate"],
                   env=child_env, check=True)
    assets = json.loads((work / "obj/project.assets.json").read_text(encoding="utf-8"))
    roots = resolve_sdks(assets, packages, args.rid)
    env_lines = [f"{variable}={root.as_posix()}" for variable, (root, _) in roots.items()]
    runtime = [root / folder for root, _ in roots.values() for folder in ("bin", "lib")
               if (root / folder).is_dir()]
    installed = Path(os.environ["GITHUB_WORKSPACE"]) / "build/vcpkg_installed"
    triplet = os.environ["VCPKG_TARGET_TRIPLET"]
    runtime += [installed / triplet / "bin", installed / triplet / "lib"]
    if args.rid == "linux-x64":
        search = [path.as_posix() for path in runtime]
        if os.environ.get("LD_LIBRARY_PATH"):
            search.append(os.environ["LD_LIBRARY_PATH"])
        env_lines.append("LD_LIBRARY_PATH=" + ":".join(search))
    else:
        write_lines(Path(os.environ["GITHUB_PATH"]), [str(path) for path in runtime])
    write_lines(Path(os.environ["GITHUB_ENV"]), env_lines)
    report = ["### Resolved native SDKs", "", "| SDK root | Version | RID |", "|---|---|---|"]
    report += [f"| {variable} | {version} | {args.rid} |" for variable, (_, version) in roots.items()]
    report += ["", "SDK/cache qualification is not full TurboP2P migration acceptance."]
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        write_lines(Path(os.environ["GITHUB_STEP_SUMMARY"]), report)
    for variable, (_, version) in roots.items():
        print(f"Resolved {variable}: {version} ({args.rid})")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"SDK restore failed: {error}", file=sys.stderr)
        raise SystemExit(1)
