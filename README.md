# lucid-auth

`lucid-auth` is a native Rust authentication library with a deliberately
tested compatibility surface for the official Better Auth JavaScript client.
It does not execute or embed a JavaScript authentication server.

The initial compatibility target is Better Auth `1.6.29` and covers:

- `getSession` and `useSession`
- username/password sign-in
- sign-out
- anonymous guest sign-in
- Better Auth session cookies and response shapes

The library keeps authentication protocol details separate from host-product
authorization. Applications provide their own permission vocabulary while
using the authenticated principal's role, actor, subject, guest grant and
assurance metadata.

This project is not affiliated with Better Auth.
