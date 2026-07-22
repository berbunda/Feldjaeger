# Xray Configuration Modification Strategy
# Purpose
This document defines how Feldjaeger modifies existing Xray configuration files.
The primary goal:
- preserve user configuration;
- minimize unintended changes;
- support future Xray versions;
- allow safe rollback.
Feldjaeger is primarily a configuration manager and only then a configuration generator.

# Core principles
## Preserve unknown data
Feldjaeger must not remove or modify configuration fields that it does not understand.
Example:
    ```json
    {
        "knownField": "...",
        "futureXrayField": "..."
    }
    ```
After modification:
    ```json
     {
        "knownField": "changed value",
        "futureXrayField": "..."
    }
    ```
Unknown fields must remain untouched whenever possible.

## Minimal modification
Feldjaeger must modify only the part of configuration required by the user action.
Example:
User edits one VLESS client.
Allowed: modify one client object
Not allowed: recreate entire inbound section

## Preserve configuration ownership
Every modified object must preserve its source information.
For config directory mode:
    ```
    /usr/local/etc/xray/

        01-inbounds.json
        02-routing.json
        03-outbounds.json
    ```
If user edits a client from: 01-inbounds.json - the modification must return to the same file.

# Configuration modes
Feldjaeger supports:
# Single file mode
Example: config.json
Modification flow:
    ```
    read file
    ↓
    parse
    ↓
    modify model
    ↓
    serialize
    ↓
    backup
    ↓
    write file
    ```
## Config directory mode
Example:
    ```
    confdir/
        inbounds.json
        routing.json
        dns.json
    ```
Modification flow:
    ```
    identify source file
    ↓
    read only affected file
    ↓
    modify section
    ↓
    backup affected file
    ↓
    write affected file
    ```

# Backup strategy
Every write operation must create a backup before modification.
Required flow:
    ```
    current configuration
    ↓
    create backup
    ↓
    write temporary file
    ↓
    validate
    ↓
    replace original file
    ```
Backup requirements:
    - backup must contain the original content;
    - backup creation failure must abort modification;
    - failed modification must not destroy working configuration.

# Atomic write
Feldjaeger must not directly overwrite configuration files.
Incorrect:
    ```
    open file
    ↓
    truncate
    ↓
    write
    ```
Correct:
    ```
    create temporary file
    ↓
    write new content
    ↓
    flush
    ↓
    replace original file
    ```
The goal is preventing broken configuration after:
    - power loss;
    - network interruption;
    - process crash.

# Validation before applying
Before uploading modified configuration:
Feldjaeger should validate the resulting configuration.
Possible validation:
    - JSON syntax;
    - internal model consistency;
    - duplicate tags;
    - required fields.
If official Xray validation mechanism is available, it should be preferred.
Invalid configuration must not replace working configuration.

# Serialization strategy
Feldjaeger should distinguish:
## Editable fields
Fields represented by Rust models.
Example:
    ```
    VLESS client email
    VLESS client UUID
    ```
## Preserved fields
Unknown JSON fields stored as:
    ```rust 
    serde_json::Value
    ```
Unknown fields must survive serialization.

# User actions
Each modification should have explicit operation type.
Example:
    ```
    AddUser
    UpdateUser
    DeleteUser
    ```
Operations should be separated from GUI.

    ```
    GUI: User clicks button
    ↓
    ApplicationService: AddUserRequest
    ↓
    Configuration layer: modify model
    ```

# Dry run support
Future versions may support: Preview changes
Before applying:
Show:
    ```
    Added client:
    email@example.com

    Removed client:
    old@example.com
    ```
No changes are applied during preview.

# Error handling
Write operation failures must be separated:
    ```
    Backup failed
    Serialization failed
    Validation failed
    Upload failed
    Permission denied
    Xray reload failed
    ```
Never report all failures as: Configuration update failed

# Xray restart policy
Configuration modification and service restart are separate operations.
After successful write:
Allowed:
    ```
    Configuration updated.
    Restart required.
    ```
Not allowed by default: Automatically restart Xray.
Automatic restart will be implemented by a separate service management layer.

# Security requirements
Configuration modification must never expose:
    - SSH passwords;
    - private keys;
    - secrets;
    - VLESS UUIDs in logs;
    - user credentials.
Sensitive information must not appear in:
    - logs;
    - error messages;
    - debug output.

# Future extensions
Possible future features:
    - configuration diff viewer;
    - rollback;
    - transaction history;
    - automatic Xray validation;
    - automatic restart;
    - multi-file transaction support.

# Important
Feldjaeger should change the configuration through an internal model, not through text search and replace.
First implementation priority is correctness and preservation of data, not feature completeness.
That is, to prohibit the approach:
    ```
    find the line email@example.com
    ↓
    replace with new@example.com
    ```
The right way:
    ```
    JSON
    ↓
    XrayConfigModel
    ↓
    изменение объекта
    ↓
    serialization
    ↓
    upload
    ```
