# Security Model

**If you have identified a security issue with Roast, please reach out via: https://github.com/thomasdesr/roast/security.**

> [!WARNING]
> Roast is experimental security code that has not undergone significant security review by lots of people. Do not use in production systems.

This document describes Roast's security properties and requirements. For technical protocol details, see [How it Works](./docs/protocol.md).

## Authentication Process

1. **Exchange of signed GetCallerIdentity payloads:**
   - Verifies the identity of both client and server using their AWS Identity
   - Ensures that only authorized IAM roles can establish connections

2. **TLS with ephemeral certificates:**
   - As a part of identity verification, each side of the roast handshake
     generates a per-connection certificates locally
   - These certificates use Go's standard library TLS implementation

## Security Considerations

**Assumptions:**
- The security of new Roast connections is fundamentally limited by the security of
  your AWS credential management. If a malicious party can access IAM
  Credentials for a role in the allowed list, they will be able to initiate or
  receive new connections. Existing connections should be unaffected.

**Design Decisions:**
- **Bulkheads between each connection**: Every connection should not share state
  with any other. I.e. it should get its own everything (key material, nonces,
  etc). The goal being to ensure that the compromise of one connection should
  not affect either the integrity or confidentiality of any other.
- **Simple and Misuse Resistant**: The audience for this library is general
  software engineers. The bar for using roast correctly must be "knowing who I'm
  supposed to be talking to". There cannot be multiple choices, or requiring
  detailed knowledge of how to configure TLS.
- **Modern TLS**: After the Roast Handshake, all communications use the latest
  available TLS (1.3 as of writing)

## Known Security Pitfalls

Areas the author was aware of during development:

- HashiCorp Vault + k8s-aws-authenticator GetCallerIdentity failures
- Replay attack considerations
- AWS credential scope and boundary enforcement

## Important Limitations

- **No formal security audit**: This implementation has not been reviewed by
  security professionals
- **Limited battle-testing**: The protocol and implementation have not been
  tested at scale
- **AWS service dependencies**: Any AWS STS service disruptions affect
  authentication
- **Credential management**: Your security posture depends entirely on AWS IAM
  credential management practices
