# Roast: Simplified mTLS for AWS

Roast simplifies deployment of mutual TLS authentication by building on top of an
existing AWS IAM identities rather than requiring a separate Certificate
Authority.

> [!WARNING]
> Roast is experimental security code that has not undergone significant
> security review by lots of people. Do not use in production systems.
> That said, if this approach interests you, would love to chat :D

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
infrastructure. If you're already using AWS IAM for identity management, then
Roast makes it easy to leverage the same system for authentication.

### Key Benefits

- **Familiar identity model** - Use your existing IAM roles for service
  authentication
- **Simpler infrastructure** - Build on what you already have
- **Reduced operational overhead** - Fewer additional services to manage
- **Automatic key rotation** - Fresh ephemeral certificates for each connection

### How It Works

Roast uses AWS SigV4 signatures combined with `sts.GetCallerIdentity` to create
verifiable identity proofs, turning your existing AWS credentials into a signing
mechanism to bootstrap TLS connections.

## Quick Start

### HTTP Services

For HTTP services, use the `rhttp2` package:

```go
// HTTP Server
clientRole, _ := arn.Parse("arn:aws:iam::123456789012:role/MyClient")
srv := &rhttp2.Server{
    Server: &http.Server{
        Handler: yourHandler,
    },
    AllowedRoles: []arn.ARN{clientRole},
}
err := srv.Serve(listener)
```

```go
// HTTP Client
serverRole, _ := arn.Parse("arn:aws:iam::123456789012:role/MyServer")
client, err := rhttp2.Client([]arn.ARN{serverRole})
resp, err := client.Get("https://server-address")
```

### TCP Connections

For lower-level TCP connection handling:

```go
// Client
serverRole, _ := arn.Parse("arn:aws:iam::123456789012:role/MyServer")
conn, err := roast.NewDialer([]arn.ARN{serverRole}).DialContext("tcp", serverAddr)
```

```go
// Server
clientRole, _ := arn.Parse("arn:aws:iam::123456789012:role/MyClient")
listener, err := roast.NewListener(rawListener, []arn.ARN{clientRole})
// for { listener.Accept() [...] }
```

## Learn More

- **[docs/protocol.md](./docs/protocol.md)** - Technical details on the protocol
  flow
- **[Security Considerations](./SECURITY.md)** - Security model and limitations
- **[API Reference](https://pkg.go.dev/github.com/thomasdesr/roast)** - Complete
  Go package documentation
