# Roast: Simplified mTLS for AWS

**Roast simplies deployment mutual TLS authentication by building on top of your
existing AWS IAM identities rather than requiring a separate Certificate
Authority.**

> [!WARNING] Roast is experimental security code that has not undergone
> significant security review by lots of people. Do not use in production
> systems. That said, if this approach interests you, would love to chat :D

## Motivation

Traditional mTLS implementations often involve operational challenges:

- **Parallel identity systems** - Managing certificates separately from your
  existing AWS IAM setup
- **Additional operational overhead** - Another service to run, monitor, and
  maintain  
- **Key management** - Handling certificate rotation, revocation, and
  distribution
- **CA infrastructure complexity** - Setting up and managing certificate
  authorities can be complex and time-consuming

## Approach

Roast takes a different approach by building on AWS's existing identity
infrastructure. If you're already already using AWS IAM for identity management,
Roast will leverages that same system for service-to-service authentication.

This approach can provide:
- **Familiar identity model** - Use your existing IAM roles for service
  authentication
- **Simpler infrastructure** - Build on what you already have
- **Reduced operational overhead** - Fewer additional services to manage
- **Automatic key rotation** - Fresh ephemeral certificates for each connection

**How it works:** Roast uses AWS SigV4 signatures combined with
`sts.GetCallerIdentity` to create verifiable identity proofs, turning your
existing AWS credentials into a signing mechanism to bootstrap secure
connections.

## Quick Start

### For HTTP

For HTTP services, use the `rhttp2` package:

```go
// HTTP Server
allowedClientRoles := mustParseRoleList("arn:aws:iam::123456789012:role/MyClient")
srv := &rhttp2.Server{
    Server: &http.Server{
        Handler: yourHandler,
    },
    AllowedRoles: allowedClientRoles,
}
err := srv.Serve(listener)

// HTTP Client
allowedServerRoles := mustParseRoleList("arn:aws:iam::123456789012:role/MyServer")
client, err := rhttp2.Client(allowedServerRoles)
resp, err := client.Get("https://server-address")
```

### Raw TCP

For lower-level TCP connections handling:

```go
// Client: specify which server roles you expect
allowedServerRoles := mustParseRoleList("arn:aws:iam::123456789012:role/MyServer")
conn, err := roast.NewDialer(allowedServerRoles).DialContext("tcp", serverAddr)

// Server: specify which client roles you expect
allowedClientRoles := mustParseRoleList("arn:aws:iam::123456789012:role/MyClient")
listener, err := roast.NewListener(rawListener, allowedClientRoles)
// for { listener.Accept() [...] }
```

## Learn More

- **[How it Works](./docs/protocol.md)** - Technical details and protocol flow
- **[Security Considerations](./SECURITY.md)** - Security model and limitations
- **[API Reference](https://pkg.go.dev/github.com/thomasdesr/roast)** - Complete
  Go package documentation
