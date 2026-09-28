# Security reporting

Use **Security → Report a vulnerability** in this GitHub repository to report
security vulnerabilities privately. Do not disclose vulnerability details in
public issues or pull requests.

Provide:

- the collector version, retrieved using `unio-collector --version`;
- the affected operating system/platform;
- a minimal synthetic reproduction; and
- relevant non-sensitive logs or error output where useful.

Do not attach AWS credentials, customer evidence, identity-vault material,
unredacted identifiers, passphrases, recovery keys, decrypted data or other
sensitive data.

Unio Collector performs read-only AWS collection and local bundle operations.
Its privacy controls reduce exposure but do not make evidence anonymous.
