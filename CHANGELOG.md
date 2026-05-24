## [0.1.41] - 2026-05-24

### 🐛 Bug Fixes

- Handle symlinked deny mount destinations
## [0.1.40] - 2026-05-24

### 🐛 Bug Fixes

- Tolerate missing host directories
- Tolerate missing host directories
- Tolerate missing host policy paths
- Tolerate missing host policy paths

### 🧪 Testing

- *(sandbox)* Cover missing host paths

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.40 [ci skip]
- Release version 0.1.40
## [0.1.39] - 2026-05-19

### 🐛 Bug Fixes

- Stop patching deleted Homebrew binary

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.39 [ci skip]
- Release version 0.1.39
## [0.1.38] - 2026-05-18

### 🐛 Bug Fixes

- Repair Linux sandbox reentry and deny negation
- Preserve host resolver runtime in sandbox
- Preserve host resolver runtime in sandbox
- Preserve runtime agent sockets in sandbox
- Avoid virtual scratch directory collisions

### 🧪 Testing

- Cover Linux host network bwrap args
- Canonicalize resolver symlink expectation

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.38 [ci skip]
- Release version 0.1.38
## [0.1.37] - 2026-05-18

### 🐛 Bug Fixes

- Stage bwrap child mountpoints under denied parents

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.37 [ci skip]
- Release version 0.1.37
## [0.1.36] - 2026-05-18

### 🐛 Bug Fixes

- Resolve filesystem policy conflicts by path specificity

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.36 [ci skip]
- Release version 0.1.36
## [0.1.35] - 2026-05-17

### 🐛 Bug Fixes

- Writable ancestor patterns grant CWD write access (#11)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.35 [ci skip]
- Release version 0.1.35
## [0.1.34] - 2026-05-16

### 🐛 Bug Fixes

- *(macos)* Use broad /System read access instead of cherry-picked subpaths (#10)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.34 [ci skip]
- Release version 0.1.34
## [0.1.33] - 2026-05-16

### 🚜 Refactor

- *(macos)* Sync seatbelt policies with openai/codex (#9)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.33 [ci skip]
- Release version 0.1.33
## [0.1.32] - 2026-05-16

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.32 [ci skip]
- Release version 0.1.32
## [0.1.31] - 2026-05-16

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.31 [ci skip]
- Release version 0.1.31
## [0.1.30] - 2026-05-16

### 🐛 Bug Fixes

- Align seatbelt with Codex parity and handle external writable/deny paths (#8)

### ⚙️ Miscellaneous Tasks

- Release version 0.1.30
## [0.1.29] - 2026-05-16

### 🐛 Bug Fixes

- Use dirs crate for home directory and add HOME read tests

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.29 [ci skip]
- Release version 0.1.29
## [0.1.28] - 2026-05-16

### 🐛 Bug Fixes

- Grant $HOME read-only access and remove default synthetic identity files

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.28 [ci skip]
- Release version 0.1.28
## [0.1.27] - 2026-05-15

### 🚀 Features

- *(npm)* Include Dawn dylib in platform packages

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.27 [ci skip]
- Release version 0.1.27
## [0.1.26] - 2026-05-15

### 🐛 Bug Fixes

- Install Dawn dylib before pkgshare snatches leftover files

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.26 [ci skip]
- Release version 0.1.26
## [0.1.25] - 2026-05-15

### 🚀 Features

- *(homebrew)* Auto-patch formula to install Dawn dylib and add rpath

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.25 [ci skip]
- Release version 0.1.25
## [0.1.24] - 2026-05-15

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.24 [ci skip]
- Release version 0.1.24
## [heimdall-sandbox-v0.1.23] - 2026-05-15

### 🐛 Bug Fixes

- Patch dist manifest checksum after WebGPU Dawn repackaging

### ⚙️ Miscellaneous Tasks

- Release version 0.1.23
## [0.1.22] - 2026-05-14

### ⚙️ Miscellaneous Tasks

- Build Linux arm64 without WebGPU
- Update changelog for v0.1.22 [ci skip]
- Release version 0.1.22
## [0.1.21] - 2026-05-14

### ⚙️ Miscellaneous Tasks

- Restore Linux arm64 release target
- Update changelog for v0.1.21 [ci skip]
- Release version 0.1.21
## [0.1.20] - 2026-05-14

### ⚙️ Miscellaneous Tasks

- Publish npm packages for built targets
- Update changelog for v0.1.20 [ci skip]
- Release version 0.1.20
## [0.1.19] - 2026-05-14

### ⚙️ Miscellaneous Tasks

- Release only WebGPU-supported Linux target
- Update changelog for v0.1.19 [ci skip]
- Release version 0.1.19
## [0.1.18] - 2026-05-14

### 🐛 Bug Fixes

- Restore WebGPU support on all targets

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.18 [ci skip]
- Release version 0.1.18
## [0.1.17] - 2026-05-13

### ⚙️ Miscellaneous Tasks

- Publish privacy filter crate before CLI
- Update changelog for v0.1.17 [ci skip]
- Release version 0.1.17
## [0.1.16] - 2026-05-13

### ⚙️ Miscellaneous Tasks

- Build x86 release on Ubuntu 24.04
- Update changelog for v0.1.16 [ci skip]
- Release version 0.1.16
## [0.1.15] - 2026-05-13

### 🐛 Bug Fixes

- Limit WebGPU provider to macOS builds

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.15 [ci skip]
- Release version 0.1.15
## [0.1.14] - 2026-05-13

### 🐛 Bug Fixes

- Avoid Linux Dawn sidecar packaging

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.14 [ci skip]
- Release version 0.1.14
## [0.1.13] - 2026-05-13

### ⚙️ Miscellaneous Tasks

- Allow custom release workflow packaging
- Update changelog for v0.1.13 [ci skip]
- Release version 0.1.13
## [0.1.12] - 2026-05-13

### 🐛 Bug Fixes

- Package WebGPU Dawn release library

### 🧪 Testing

- Bound privacy filter overflow tests

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.12 [ci skip]
- Release version 0.1.12
## [0.1.11] - 2026-05-13

### 🚀 Features

- Add ONNX privacy filter (#3)

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.11 [ci skip]
- Release version 0.1.11
## [0.1.10] - 2026-05-08

### 🐛 Bug Fixes

- Avoid crates.io API checks during publish

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.10 [ci skip]
- Release version 0.1.10
## [0.1.9] - 2026-05-08

### 🐛 Bug Fixes

- Use Node tooling for npm package assembly
- Handle downloaded cargo-dist artifact layout
- Retry crates.io publish attempts

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.9 [ci skip]
- Release version 0.1.9
## [0.1.8] - 2026-05-08

### 🚀 Features

- Add registry publishing automation

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.8 [ci skip]
- Release version 0.1.8
## [0.1.7] - 2026-05-07

### 📚 Documentation

- Update README for macOS Seatbelt, fragment files, and new install options

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.7 [ci skip]
- Release version 0.1.7
## [0.1.6] - 2026-05-07

### 🚀 Features

- *(release)* Add macOS CI and Apple Silicon artifacts

### 📚 Documentation

- Add Linux eBPF egress solution analysis

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.6 [ci skip]
- Release version 0.1.6
## [0.1.5] - 2026-05-07

### 🚀 Features

- Add macOS Seatbelt sandbox

### ⚙️ Miscellaneous Tasks

- Add project agent definitions
- Update changelog for v0.1.5 [ci skip]
- Release version 0.1.5
## [0.1.4] - 2026-05-07

### 📚 Documentation

- Add README and MIT license

### ⚙️ Miscellaneous Tasks

- Update changelog for v0.1.4 [ci skip]
- Release version 0.1.4
## [0.1.3] - 2026-05-07

### ⚙️ Miscellaneous Tasks

- Regenerate release workflow
- Update changelog for v0.1.3 [ci skip]
- Release version 0.1.3
## [0.1.2] - 2026-05-07

### ⚙️ Miscellaneous Tasks

- Add release automation
- Install rust formatting components
- Update changelog for v0.1.1 [ci skip]
- Release version 0.1.1
- Ensure release tags are created
- Update changelog for v0.1.2 [ci skip]
- Release version 0.1.2
