# lucid-auth

`lucid-auth` is a native Rust authentication library with a deliberately
tested compatibility surface for the official Better Auth JavaScript client.
It does not execute or embed a JavaScript authentication server.

The initial compatibility target is Better Auth `1.6.29` and covers:

- `getSession` and `useSession`
- username/password sign-in
- sign-out
- anonymous guest sign-in
- passkey enrollment, listing and sign-in through `@better-auth/passkey`
- Better Auth session cookies and response shapes

The library keeps authentication protocol details separate from host-product
authorization. Applications provide their own permission vocabulary while
using the authenticated principal's role, actor, subject, guest grant and
assurance metadata.

Passkey enrollment requires an existing session. Authenticating a passkey
from a password session produces `password_and_passkey` assurance, allowing a
host to require step-up MFA for sensitive operations. WebAuthn relying-party
configuration is explicit and must use HTTPS except for the browser's
`localhost` development exception.

This project is not affiliated with Better Auth.
