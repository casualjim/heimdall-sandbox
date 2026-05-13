## ADDED Requirements

### Requirement: Overflow input is windowed
The privacy-filter runtime SHALL process input that exceeds the usable model token limit by splitting it into overlapping tokenizer-aligned windows instead of truncating or rejecting the input for length alone.

#### Scenario: Long input exceeds context
- **WHEN** privacy-filter redaction receives text whose encoded token count is greater than the usable model token limit
- **THEN** the runtime processes the text as multiple overlapping model windows
- **AND** every offset-bearing token from the original input is included in at least one window

#### Scenario: Input fits context
- **WHEN** privacy-filter redaction receives text whose encoded token count is less than or equal to the usable model token limit
- **THEN** the runtime processes the text as a single model window

### Requirement: Window spans use original byte offsets
The privacy-filter runtime SHALL preserve original input byte offsets through token windowing so decoded sensitive spans apply to the original text.

#### Scenario: Sensitive span appears after first window
- **WHEN** a sensitive span is detected in a window that starts after the beginning of the original input
- **THEN** the decoded span byte range refers to the original input byte positions
- **AND** redaction replaces the matching original text range

#### Scenario: Window boundary overlaps source text
- **WHEN** adjacent token windows overlap
- **THEN** tokens in the overlap retain the same original byte offsets in both windows

### Requirement: Overlapping window results are merged before redaction
The privacy-filter runtime SHALL merge and deduplicate sensitive spans from all windows before applying redaction to the original text.

#### Scenario: Duplicate detection in overlap
- **WHEN** the same sensitive text is detected in two overlapping windows
- **THEN** the runtime emits one redaction for that original byte range

#### Scenario: Partially overlapping detections
- **WHEN** two detected sensitive spans overlap in original byte coordinates
- **THEN** the runtime applies a deterministic privacy-preserving redaction without exposing the overlapped raw text

### Requirement: Usable token limit comes from model assets
The privacy-filter runtime SHALL determine its usable window size from cached model or tokenizer metadata loaded with the selected privacy-filter assets.

#### Scenario: Metadata defines tokenizer limit
- **WHEN** the cached tokenizer metadata defines a maximum token length
- **THEN** the runtime uses that metadata to bound model windows

#### Scenario: Metadata is unusable
- **WHEN** the cached model assets do not provide a usable token limit for windowing
- **THEN** privacy-filter runtime loading fails with a configuration or asset error
