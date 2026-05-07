## ADDED Requirements

### Requirement: Platform-specific isolation dispatch
The core runtime SHALL dispatch requests that need OS-level isolation to the sandbox implementation for the current platform and SHALL NOT fall back to direct execution when platform sandbox setup fails.

#### Scenario: macOS isolation routes to Seatbelt
- **WHEN** the system runs on macOS and an execution request needs filesystem or network isolation
- **THEN** the core runtime executes the request through the macOS Seatbelt path

#### Scenario: Linux isolation remains bubblewrap-backed
- **WHEN** the system runs on Linux and an execution request needs filesystem or network isolation
- **THEN** the core runtime executes the request through the Linux bubblewrap path

#### Scenario: Non-isolated requests remain direct
- **WHEN** an execution request uses host networking and contains no filesystem controls
- **THEN** the core runtime executes the request through the existing direct execution path

#### Scenario: Unsupported platform isolation fails closed
- **WHEN** the current platform has no supported OS sandbox implementation and an execution request needs filesystem or network isolation
- **THEN** the system exits with the sandbox misconfiguration code
- **AND** the requested command is not executed directly on the host

### Requirement: Shared policy compatibility
The CLI and core runtime SHALL accept the shared sandbox policy shape across supported platforms while allowing platform-specific implementations to define compatibility behavior for fields that have no direct platform equivalent.

#### Scenario: macOS accepts proc compatibility field
- **WHEN** a macOS JSON policy contains `proc: "none"` or `proc: "default"`
- **THEN** the CLI parses the policy successfully and carries the proc mode in the core execution request

#### Scenario: macOS accepts virtual filesystem compatibility field
- **WHEN** a macOS JSON policy contains `filesystem.virtual`
- **THEN** the CLI parses the policy successfully and carries the virtual entries in the core execution request

#### Scenario: Shared policy validation remains syntactic at the CLI boundary
- **WHEN** a JSON policy contains shared sandbox fields with valid syntax
- **THEN** the CLI creates a core execution request without applying platform-specific business behavior in the parser
