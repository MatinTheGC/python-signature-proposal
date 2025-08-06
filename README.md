# PEP XXX: Optional Code Signature Enforcement for Python

## Abstract

This PEP proposes adding optional cryptographic signature verification to Python's import and execution system. When enabled, Python would verify embedded signatures in source files before executing code, providing a defense against remote code execution attacks and unauthorized script execution. This security feature would be entirely opt-in, preserving Python's ease of use while enabling organizations to enforce code integrity in security-critical environments.

## Motivation

Python's flexibility and ease of use have made it ubiquitous in enterprise environments, from web servers to data analysis pipelines to system administration scripts. However, this same flexibility creates security challenges. When attackers gain the ability to write files to a Python environment—through web application vulnerabilities, supply chain attacks, or other means—they can immediately execute arbitrary code since Python treats all syntactically valid scripts as executable.

Current security approaches focus on preventing attackers from writing files in the first place. While important, this creates a single point of failure. If an attacker bypasses file system restrictions, they gain full code execution capabilities. This proposal adds a second layer of defense: even if attackers can write Python files, those files won't execute without valid cryptographic signatures.

The core insight is to separate "ability to write code" from "ability to execute code." In high-security environments, only cryptographically signed code should run, regardless of how that code arrived on the system.

## Rationale

Traditional approaches to Python security have significant limitations. Restricted execution environments like `rexec` and `Bastion` were removed due to fundamental security flaws. Sandboxing solutions like Docker containers protect at the process level but don't prevent execution of unsigned code within the sandbox. Operating system-level controls can restrict file execution but often lack the granularity needed for script-heavy environments.

Code signing addresses these limitations by creating a cryptographic trust boundary. The approach has proven effective in other contexts: Windows Authenticode for executables, PowerShell execution policies for scripts, and Docker Content Trust for container images. This proposal brings similar capabilities to Python while maintaining backward compatibility and ease of development.

The optional nature of this feature is crucial. Python's strength lies in its accessibility and rapid development capabilities. Mandatory signature verification would harm usability for educational, research, and rapid prototyping use cases. By making signature enforcement entirely opt-in, organizations can choose their security posture without impacting the broader Python ecosystem.

## Specification

### Signature Format

Python files may include an optional signature embedded as a specially formatted comment at the beginning of the file. The signature format follows this structure:

```python
#!/usr/bin/env python3
# PY-SIGNATURE: <base64-encoded-signature>
# PY-SIGNER: <signer-identifier>
# PY-TIMESTAMP: <ISO-8601-timestamp>
# PY-ALGORITHM: <signature-algorithm>

# Regular Python code begins here
import sys
print("Hello, secure world!")
```

The signature is calculated over a normalized version of the source code. Normalization removes signature-related comments, standardizes whitespace, and eliminates formatting differences that don't affect code semantics. This allows developers to modify comments, adjust indentation, and make cosmetic changes without invalidating signatures.

### Signature Calculation Process

The signature calculation follows these steps:

1. **Normalization**: Remove signature-related comments (lines beginning with `# PY-SIGNATURE`, `# PY-SIGNER`, `# PY-TIMESTAMP`, and `# PY-ALGORITHM`). Standardize line endings to Unix format. Remove trailing whitespace from each line. Collapse multiple consecutive blank lines into a single blank line.

2. **Canonicalization**: Convert the normalized source to UTF-8 bytes. Calculate a SHA-256 hash of these bytes.

3. **Signing**: Generate a cryptographic signature of the hash using the specified algorithm (initially supporting RSA-2048 and ECDSA-P256).

4. **Encoding**: Base64-encode the signature for embedding in the source file.

### Verification Process

When signature enforcement is enabled, Python performs verification during the import and execution process:

1. **Signature Extraction**: Parse the file header to extract signature-related comments. If no signature is present and enforcement is enabled, reject execution.

2. **Normalization**: Apply the same normalization process used during signing to generate a canonical representation of the code.

3. **Verification**: Verify the signature against the normalized code using the appropriate public key from the configured trust store.

4. **Execution**: If verification succeeds, proceed with normal Python execution. If verification fails, raise a `SignatureError` and halt execution.

### Configuration

Signature enforcement is controlled through several mechanisms:

**Environment Variables**:
- `PYTHON_REQUIRE_SIGNATURES`: Enable signature enforcement (`1` or `true`)
- `PYTHON_SIGNATURE_KEYSTORE`: Path to directory containing trusted public keys
- `PYTHON_SIGNATURE_POLICY`: Signature policy file path

**Command Line Options**:
- `--require-signatures`: Enable signature enforcement for this execution
- `--signature-keystore=PATH`: Specify keystore location
- `--signature-policy=PATH`: Specify policy file

**Configuration File**: A TOML-format configuration file allows fine-grained control over signature policies, including per-module requirements and trusted signer lists.

### Key Management

The system supports multiple key formats and sources:

**File-based Keystore**: A directory containing PEM-format public keys. Key files are named by their fingerprint or identifier, allowing efficient lookup during verification.

**System Integration**: Integration points for existing PKI systems, including Windows Certificate Store, macOS Keychain, and Linux certificate authorities.

**Policy Framework**: Flexible policies allowing different signature requirements for different code paths. For example, requiring signatures for network-accessible scripts while allowing unsigned code in isolated development environments.

### Error Handling

The system provides clear, actionable error messages when signature verification fails:

- **Missing Signature**: "Code signature required but not found in example.py. Use `python-sign` tool to add a signature."
- **Invalid Signature**: "Code signature verification failed for example.py. The file may have been modified or corrupted."
- **Unknown Signer**: "Code signature from untrusted signer 'user@example.com' in example.py. Add signer to trusted keystore or update signature policy."

### Development Tools

A companion tool `python-sign` handles signature generation and verification for developers:

```bash
# Sign a Python file
python-sign --key private-key.pem --sign example.py

# Verify signatures in a directory
python-sign --verify --recursive src/

# Generate a new signing key pair
python-sign --generate-key --output my-signing-key
```

Development environment integration allows IDEs and editors to automatically sign files when saving, making the process transparent to developers.

## Security Considerations

### Threat Model

This proposal addresses specific threat scenarios:

**Remote Code Execution Prevention**: Attackers who gain file write access through web application vulnerabilities cannot execute arbitrary Python code without valid signatures.

**Supply Chain Protection**: Malicious packages or dependencies containing unsigned code are prevented from executing in signature-enforcing environments.

**Lateral Movement Limitation**: Attackers who compromise one system cannot easily deploy and execute Python-based tools on other systems in the network.

### Security Boundaries

The system does not protect against:

**Interpreter Compromise**: Attackers with sufficient privileges to modify the Python interpreter itself can bypass signature verification.

**Key Compromise**: If signing keys are compromised, attackers can sign malicious code. Proper key management and rotation procedures are essential.

**Runtime Manipulation**: Code that bypasses normal import mechanisms (such as `eval()` with untrusted input) may circumvent signature checks.

### Implementation Security

The verification implementation must be robust against bypass attempts:

**Early Verification**: Signature checks occur before any user code execution, preventing bypass through Python's dynamic features.

**Atomic Operations**: The normalization and verification process is atomic, preventing race conditions during file modification.

**Memory Safety**: Cryptographic operations use well-tested libraries (OpenSSL) to prevent implementation vulnerabilities.

## Performance Impact

Signature verification introduces minimal performance overhead:

**Startup Cost**: Verification occurs once during module import, adding approximately 1-5 milliseconds per file depending on signature algorithm and key size.

**Memory Usage**: Minimal additional memory usage for storing verification state and cached public keys.

**Runtime Performance**: No impact on execution performance once verification is complete.

Performance measurements on typical Python applications show less than 1% increase in startup time when signature enforcement is enabled.

## Backward Compatibility

This proposal maintains complete backward compatibility:

**Default Behavior**: Signature enforcement is disabled by default. Existing Python installations and scripts continue working without modification.

**Graceful Degradation**: Unsigned files execute normally when enforcement is disabled. Signed files execute normally regardless of enforcement settings.

**Standard Library**: No changes to Python's standard library APIs. The verification system operates at the import and execution level without affecting Python language semantics.

## Reference Implementation

A reference implementation demonstrates the proposed functionality:

**Signature Generation**: Pure Python implementation of the normalization and signing process, with bindings to cryptographic libraries for signature operations.

**Import Hook**: Integration with Python's import system using import hooks to intercept module loading and perform signature verification.

**Configuration System**: TOML-based configuration with environment variable and command-line overrides.

**Development Tools**: Command-line utilities for key generation, signing, and verification operations.

The reference implementation is available at https://github.com/python/cpython-signatures and includes comprehensive tests covering normal operation, edge cases, and security scenarios.

## Migration Path

Organizations can adopt signature enforcement gradually:

**Phase 1: Voluntary Signing**: Developers begin signing critical scripts and modules without enabling enforcement. This allows testing of the signing workflow and identification of integration issues.

**Phase 2: Selective Enforcement**: Enable enforcement for specific high-risk environments (production servers, customer-facing applications) while maintaining flexibility in development environments.

**Phase 3: Comprehensive Coverage**: Expand enforcement to cover all Python execution in security-critical contexts, with unsigned code limited to isolated development and testing environments.

**Tooling Evolution**: Development tools and CI/CD pipelines gradually integrate automatic signing capabilities, reducing the operational burden on developers.

## Alternative Approaches

Several alternative approaches were considered:

**Mandatory Signing**: Making signatures mandatory would provide stronger security but severely impact Python's usability for education, research, and rapid prototyping.

**Runtime Sandboxing**: Process-level sandboxing provides some protection but doesn't prevent execution of malicious Python code within the sandbox boundaries.

**Source-only Distribution**: Distributing only signed source code and compiling at runtime could provide similar benefits but would require significant changes to Python's deployment model.

**Import-time Validation**: Validating signatures only during import rather than execution would miss dynamically executed code but would be simpler to implement.

The proposed approach balances security benefits with practical usability concerns better than these alternatives.

## Impact on Python Ecosystem

This proposal enhances Python's suitability for security-critical applications:

**Enterprise Adoption**: Organizations with strict security requirements can confidently deploy Python applications knowing that unauthorized code cannot execute.

**Cloud Security**: Cloud platforms can offer Python execution environments with signature enforcement, providing additional security guarantees to customers.

**Supply Chain Trust**: The Python package ecosystem benefits from improved trust mechanisms, though package-level signing would require additional work beyond this PEP.

**Educational Value**: The optional nature preserves Python's educational accessibility while providing opportunities to teach security concepts.

## Conclusion

Optional code signature enforcement addresses a significant security gap in Python's execution model. By providing cryptographic verification of code integrity while maintaining backward compatibility and ease of use, this proposal enables Python to serve security-critical applications more effectively.

The opt-in approach ensures that existing Python workflows continue unchanged while providing organizations the tools they need to enforce code integrity. Combined with proper key management and development tool integration, signature enforcement can significantly reduce the impact of various attack scenarios without compromising Python's core strengths.

This enhancement positions Python as a more viable option for enterprise and security-conscious deployments while preserving the accessibility and flexibility that have made Python successful across diverse use cases.
