#!/usr/bin/env python3
"""
Release Script for libserver

This script prepares packaged tarballs and release versions for GitHub releases.
It supports multiple compiler toolchains and creates separate builds for each.

Usage:
    ./release.py [OPTIONS]

Options:
    -v, --version VERSION   Set the release version (e.g., 1.0.0)
    -o, --output DIR        Output directory for release artifacts (default: ./release)
    -c, --clean             Clean build directories before building
    -s, --source-only       Create source tarball only (skip builds)
    --sign                  Sign the release tarballs with GPG
    --compilers COMP        Comma-separated list of compilers to use (default: all available)
    -j, --jobs N            Number of parallel build jobs (default: auto)
    -h, --help              Show this help message

Examples:
    ./release.py -v 1.0.0
    ./release.py -v 1.0.0 --compilers clang,filc
    ./release.py -v 2.0.0 -o dist --source-only
"""

import argparse
import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ANSI Colors
class Colors:
    RED = '\033[0;91m'
    GREEN = '\033[0;92m'
    YELLOW = '\033[0;93m'
    BLUE = '\033[0;94m'
    CYAN = '\033[0;96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


@dataclass
class Compiler:
    """Compiler toolchain configuration."""
    name: str           # Short name for the compiler (used in tarball names)
    cc: str             # C compiler path/command
    cxx: str            # C++ compiler path/command
    description: str    # Human-readable description


# Define available compiler configurations
COMPILER_CONFIGS = [
    Compiler(
        name="clang",
        cc="clang",
        cxx="clang++",
        description="Clang/LLVM"
    ),
    Compiler(
        name="gcc",
        cc="gcc",
        cxx="g++",
        description="GCC"
    ),
    Compiler(
        name="filc",
        cc="/opt/fil/bin/filcc",
        cxx="/opt/fil/bin/filc++",
        description="Fil-C (memory-safe C)"
    ),
]


def print_header(msg: str) -> None:
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}  {msg}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}{'=' * 60}{Colors.RESET}")


def print_step(msg: str) -> None:
    print(f"{Colors.BOLD}{Colors.BLUE}>>> {msg}{Colors.RESET}")


def print_success(msg: str) -> None:
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")


def print_warning(msg: str) -> None:
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.RESET}")


def print_error(msg: str) -> None:
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}")


def die(msg: str) -> None:
    print_error(msg)
    sys.exit(1)


def run_command(cmd: list[str], cwd: Optional[Path] = None, env: Optional[dict] = None) -> subprocess.CompletedProcess:
    """Run a command and return the result."""
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=merged_env,
        capture_output=True,
        text=True
    )
    return result


def get_compiler_version(compiler_path: str) -> str:
    """Get the version string of a compiler."""
    try:
        result = subprocess.run(
            [compiler_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            # Return first line of version output
            return result.stdout.strip().split('\n')[0]
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "unknown"


def check_compiler_available(compiler: Compiler) -> bool:
    """Check if a compiler is available on the system."""
    cc_path = Path(compiler.cc)
    cxx_path = Path(compiler.cxx)
    
    # Check if it's an absolute path
    if cc_path.is_absolute():
        return cc_path.exists() and cxx_path.exists()
    
    # Check if it's in PATH
    return shutil.which(compiler.cc) is not None and shutil.which(compiler.cxx) is not None


def get_available_compilers(requested: Optional[list[str]] = None) -> list[Compiler]:
    """Get list of available compilers, optionally filtered by request."""
    available = []
    
    for compiler in COMPILER_CONFIGS:
        if check_compiler_available(compiler):
            if requested is None or compiler.name in requested:
                available.append(compiler)
        elif requested and compiler.name in requested:
            print_warning(f"Requested compiler '{compiler.name}' not available")
    
    return available


def get_git_version(project_root: Path) -> str:
    """Get version from git tags."""
    # Try exact tag match
    result = run_command(["git", "describe", "--tags", "--exact-match"], cwd=project_root)
    if result.returncode == 0:
        return result.stdout.strip().lstrip('v')
    
    # Get latest tag and append dev info
    result = run_command(["git", "describe", "--tags", "--abbrev=0"], cwd=project_root)
    latest_tag = result.stdout.strip() if result.returncode == 0 else "v0.0.0"
    
    result = run_command(["git", "rev-list", f"{latest_tag}..HEAD", "--count"], cwd=project_root)
    commits_since = result.stdout.strip() if result.returncode == 0 else "0"
    
    result = run_command(["git", "rev-parse", "--short", "HEAD"], cwd=project_root)
    short_sha = result.stdout.strip() if result.returncode == 0 else "unknown"
    
    return f"{latest_tag.lstrip('v')}-dev.{commits_since}+{short_sha}"


def create_checksum(file_path: Path) -> Path:
    """Create SHA256 checksum for a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256_hash.update(chunk)
    
    checksum_path = file_path.with_suffix(file_path.suffix + ".sha256")
    checksum_path.write_text(sha256_hash.hexdigest())
    print_success(f"Created checksum: {checksum_path.name}")
    return checksum_path


def sign_file(file_path: Path) -> Optional[Path]:
    """Sign a file with GPG."""
    sig_path = file_path.with_suffix(file_path.suffix + ".asc")
    print_step(f"Signing {file_path.name}...")
    
    result = run_command(["gpg", "--armor", "--detach-sign", "--output", str(sig_path), str(file_path)])
    if result.returncode != 0:
        print_error(f"Failed to sign {file_path.name}: {result.stderr}")
        return None
    
    print_success(f"Created signature: {sig_path.name}")
    return sig_path


def create_source_tarball(project_root: Path, output_dir: Path, project_name: str, 
                          version: str, sign: bool = False) -> Path:
    """Create source tarball from git-tracked files."""
    print_step("Creating source tarball...")
    
    tarball_name = f"{project_name}-{version}-source"
    tarball_path = output_dir / f"{tarball_name}.tar.gz"
    
    with tempfile.TemporaryDirectory() as temp_dir:
        export_dir = Path(temp_dir) / f"{project_name}-{version}"
        export_dir.mkdir()
        
        # Export from git
        result = run_command(["git", "archive", "HEAD"], cwd=project_root)
        if result.returncode != 0:
            die(f"Failed to export git archive: {result.stderr}")
        
        # Extract archive
        extract_proc = subprocess.run(
            ["tar", "-x"],
            input=result.stdout.encode() if isinstance(result.stdout, str) else result.stdout,
            cwd=export_dir,
            capture_output=True
        )
        
        # Actually, let's do this properly
        result = subprocess.run(
            ["git", "archive", "--format=tar", "HEAD"],
            cwd=project_root,
            capture_output=True
        )
        if result.returncode != 0:
            die("Failed to create git archive")
        
        subprocess.run(
            ["tar", "-x"],
            input=result.stdout,
            cwd=export_dir,
            check=True
        )
        
        # Create VERSION file
        (export_dir / "VERSION").write_text(version)
        
        # Create tarball
        with tarfile.open(tarball_path, "w:gz") as tar:
            tar.add(export_dir, arcname=f"{project_name}-{version}")
    
    print_success(f"Created source tarball: {tarball_path.name}")
    create_checksum(tarball_path)
    
    if sign:
        sign_file(tarball_path)
    
    return tarball_path


def build_with_compiler(project_root: Path, build_dir: Path, compiler: Compiler, 
                        version: str, jobs: int) -> bool:
    """Build the project with a specific compiler."""
    print_step(f"Building with {compiler.description} ({compiler.name})...")
    
    # Clean and create build directory
    if build_dir.exists():
        shutil.rmtree(build_dir)
    build_dir.mkdir(parents=True)
    
    # Configure with CMake
    cmake_cmd = [
        "cmake",
        "-S", str(project_root),
        "-B", str(build_dir),
        "-DCMAKE_BUILD_TYPE=Release",
        f"-DCMAKE_C_COMPILER={compiler.cc}",
        f"-DCMAKE_CXX_COMPILER={compiler.cxx}",
        f"-DPROJECT_VERSION={version}",
    ]
    
    result = run_command(cmake_cmd)
    if result.returncode != 0:
        print_error(f"CMake configure failed for {compiler.name}:")
        print(result.stderr)
        return False
    
    # Build
    build_cmd = [
        "cmake",
        "--build", str(build_dir),
        "--config", "Release",
        "-j", str(jobs)
    ]
    
    result = run_command(build_cmd)
    if result.returncode != 0:
        print_error(f"Build failed for {compiler.name}:")
        print(result.stderr)
        return False
    
    print_success(f"Build completed with {compiler.description}")
    return True


def create_binary_tarball(project_root: Path, build_dir: Path, output_dir: Path,
                          project_name: str, version: str, compiler: Compiler,
                          sign: bool = False) -> Optional[Path]:
    """Create binary tarball for a specific compiler build."""
    system = platform.system().lower()
    arch = platform.machine()
    
    tarball_name = f"{project_name}-{version}-{system}-{arch}-{compiler.name}"
    tarball_path = output_dir / f"{tarball_name}.tar.gz"
    
    print_step(f"Creating binary tarball for {compiler.description}...")
    
    with tempfile.TemporaryDirectory() as temp_dir:
        staging_dir = Path(temp_dir) / f"{project_name}-{version}"
        lib_dir = staging_dir / "lib"
        include_dir = staging_dir / "include"
        doc_dir = staging_dir / "share" / "doc" / project_name
        
        lib_dir.mkdir(parents=True)
        include_dir.mkdir(parents=True)
        doc_dir.mkdir(parents=True)
        
        # Copy library files
        for lib_file in build_dir.glob("libserver.*"):
            if lib_file.is_file():
                shutil.copy2(lib_file, lib_dir)
        
        # Copy headers
        src_include = project_root / "include"
        if src_include.exists():
            shutil.copytree(src_include, include_dir, dirs_exist_ok=True)
        
        # Copy documentation
        for doc_name in ["README.md", "README", "LICENSE", "LICENSE.md", "CHANGELOG.md", "CHANGELOG"]:
            doc_file = project_root / doc_name
            if doc_file.exists():
                shutil.copy2(doc_file, doc_dir)
        
        # Create VERSION file
        (staging_dir / "VERSION").write_text(version)
        
        # Create COMPILER_INFO file
        cc_version = get_compiler_version(compiler.cc)
        cxx_version = get_compiler_version(compiler.cxx)
        (staging_dir / "COMPILER_INFO").write_text(
            f"Compiler: {compiler.description}\n"
            f"CC: {compiler.cc}\n"
            f"CC Version: {cc_version}\n"
            f"CXX: {compiler.cxx}\n"
            f"CXX Version: {cxx_version}\n"
        )
        
        # Create install script
        install_script = staging_dir / "install.sh"
        install_script.write_text('''#!/usr/bin/env bash
set -euo pipefail

PREFIX="${1:-/usr/local}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing to ${PREFIX}..."

mkdir -p "${PREFIX}/lib"
mkdir -p "${PREFIX}/include"

cp -r "${SCRIPT_DIR}/lib/"* "${PREFIX}/lib/"
cp -r "${SCRIPT_DIR}/include/"* "${PREFIX}/include/"

# Update library cache on Linux
if [[ "$(uname -s)" == "Linux" ]] && command -v ldconfig &> /dev/null; then
    ldconfig 2>/dev/null || true
fi

echo "Installation complete!"
''')
        install_script.chmod(0o755)
        
        # Create tarball
        with tarfile.open(tarball_path, "w:gz") as tar:
            tar.add(staging_dir, arcname=f"{project_name}-{version}")
    
    print_success(f"Created binary tarball: {tarball_path.name}")
    create_checksum(tarball_path)
    
    if sign:
        sign_file(tarball_path)
    
    return tarball_path


def generate_release_notes(output_dir: Path, project_name: str, version: str,
                           compilers: list[Compiler]) -> Path:
    """Generate release notes template."""
    print_step("Generating release notes...")
    
    system = platform.system().lower()
    arch = platform.machine()
    
    notes_path = output_dir / "RELEASE_NOTES.md"
    
    compiler_list = "\n".join([f"- **{c.name}**: {c.description}" for c in compilers])
    
    # Gather checksums
    checksums = []
    for checksum_file in sorted(output_dir.glob("*.sha256")):
        filename = checksum_file.stem  # Remove .sha256
        checksum = checksum_file.read_text().strip()
        checksums.append(f"{filename}: {checksum}")
    
    checksums_text = "\n".join(checksums)
    
    notes_content = f"""# {project_name} v{version}

## Release Date
{subprocess.run(['date', '+%Y-%m-%d'], capture_output=True, text=True).stdout.strip()}

## Highlights
- 

## Available Builds
This release includes binaries built with multiple compilers:
{compiler_list}

## Changes
### Added
- 

### Changed
- 

### Fixed
- 

### Removed
- 

## Installation

### From Source
```bash
tar -xzf {project_name}-{version}-source.tar.gz
cd {project_name}-{version}
mkdir build && cd build
cmake ..
make
sudo make install
```

### Binary Package (Clang)
```bash
tar -xzf {project_name}-{version}-{system}-{arch}-clang.tar.gz
cd {project_name}-{version}
sudo ./install.sh
```

### Binary Package (Fil-C)
```bash
tar -xzf {project_name}-{version}-{system}-{arch}-filc.tar.gz
cd {project_name}-{version}
sudo ./install.sh
```

## Checksums
```
{checksums_text}
```

## Compiler Information
Each binary package includes a `COMPILER_INFO` file with details about the compiler used.
"""
    
    notes_path.write_text(notes_content)
    print_success(f"Generated release notes: {notes_path.name}")
    return notes_path


def print_summary(output_dir: Path, version: str, compilers: list[Compiler]) -> None:
    """Print release summary."""
    print_header("Release Summary")
    
    print(f"{Colors.BOLD}Version:{Colors.RESET}  {version}")
    print(f"{Colors.BOLD}Output:{Colors.RESET}   {output_dir}")
    print(f"{Colors.BOLD}Compilers:{Colors.RESET}")
    for compiler in compilers:
        print(f"  - {compiler.description} ({compiler.name})")
    print()
    print(f"{Colors.BOLD}Generated Files:{Colors.RESET}")
    
    for file_path in sorted(output_dir.iterdir()):
        if file_path.is_file():
            size = file_path.stat().st_size
            if size > 1024 * 1024:
                size_str = f"{size / (1024 * 1024):.1f}M"
            elif size > 1024:
                size_str = f"{size / 1024:.1f}K"
            else:
                size_str = f"{size}B"
            print(f"  - {file_path.name} ({size_str})")
    
    print()
    print(f"{Colors.BOLD}{Colors.GREEN}Release preparation complete!{Colors.RESET}")
    print()
    print("To create a GitHub release:")
    print(f"  1. Tag the release: git tag -a v{version} -m 'Release v{version}'")
    print(f"  2. Push the tag: git push origin v{version}")
    print(f"  3. Create release on GitHub and upload the files from {output_dir}/")
    print()
    print("Or use GitHub CLI:")
    tarball_files = " ".join([str(f) for f in output_dir.glob("*.tar.gz")])
    checksum_files = " ".join([str(f) for f in output_dir.glob("*.sha256")])
    print(f"  gh release create v{version} {tarball_files} {checksum_files} \\")
    print(f"     -t 'v{version}' -F {output_dir}/RELEASE_NOTES.md")


def main():
    parser = argparse.ArgumentParser(
        description="Release script for libserver with multi-compiler support",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -v 1.0.0
  %(prog)s -v 1.0.0 --compilers clang,filc
  %(prog)s -v 2.0.0 -o dist --source-only
        """
    )
    
    parser.add_argument("-v", "--version", help="Release version (e.g., 1.0.0)")
    parser.add_argument("-o", "--output", default="release", help="Output directory (default: ./release)")
    parser.add_argument("-c", "--clean", action="store_true", help="Clean build directories before building")
    parser.add_argument("-s", "--source-only", action="store_true", help="Create source tarball only")
    parser.add_argument("--sign", action="store_true", help="Sign release tarballs with GPG")
    parser.add_argument("--compilers", help="Comma-separated list of compilers (default: all available)")
    parser.add_argument("-j", "--jobs", type=int, default=os.cpu_count() or 4, help="Parallel build jobs")
    
    args = parser.parse_args()
    
    # Setup paths
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    project_name = "libserver"
    
    output_dir = Path(args.output)
    if not output_dir.is_absolute():
        output_dir = project_root / output_dir
    
    print_header(f"{project_name} Release Builder")
    
    # Check dependencies
    for dep in ["git", "cmake", "make", "tar"]:
        if not shutil.which(dep):
            die(f"Required dependency '{dep}' not found")
    
    if args.sign and not shutil.which("gpg"):
        die("GPG is required for signing but not found")
    
    # Get available compilers
    requested_compilers = args.compilers.split(",") if args.compilers else None
    compilers = get_available_compilers(requested_compilers)
    
    if not args.source_only and not compilers:
        die("No compilers available. Install clang, gcc, or filc.")
    
    print(f"{Colors.BOLD}Available compilers:{Colors.RESET}")
    for compiler in compilers:
        print(f"  - {compiler.description} ({compiler.name})")
    print()
    
    # Get version
    version = args.version
    if not version:
        version = get_git_version(project_root)
        print_warning(f"No version specified, using: {version}")
        response = input("Continue with this version? [Y/n] ").strip().lower()
        if response == 'n':
            die("Please specify a version with -v/--version")
    
    version = version.lstrip('v')
    print(f"{Colors.BOLD}Preparing release v{version}{Colors.RESET}")
    print()
    
    # Create output directory
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create source tarball
    create_source_tarball(project_root, output_dir, project_name, version, args.sign)
    
    # Build with each compiler
    if not args.source_only:
        successful_compilers = []
        
        for compiler in compilers:
            build_dir = project_root / f"build_release_{compiler.name}"
            
            if build_with_compiler(project_root, build_dir, compiler, version, args.jobs):
                tarball = create_binary_tarball(
                    project_root, build_dir, output_dir,
                    project_name, version, compiler, args.sign
                )
                if tarball:
                    successful_compilers.append(compiler)
            
            # Optionally clean build directory
            if args.clean and build_dir.exists():
                shutil.rmtree(build_dir)
        
        if not successful_compilers:
            die("All builds failed!")
        
        compilers = successful_compilers
    
    # Generate release notes
    generate_release_notes(output_dir, project_name, version, compilers)
    
    # Print summary
    print_summary(output_dir, version, compilers)


if __name__ == "__main__":
    main()
