# How Roast Works

> [!NOTE]
> This section assumes some familiarity with AWS IAM roles but not intimate knowledge of AWS internals.

For a quick overview and getting started, see the [README](../README.md). For security considerations and limitations, see [SECURITY.md](../SECURITY.md).

## Protocol Overview

**tl;dr:**

1. Using SigV4 signed `sts.GetCallerIdentity` requests to provide a proof of
   identity with an attached ephemeral CA public key
2. Generate ephemeral client & server TLS certificates and use them to establish an mTLS verified connection

## High-Level Walkthrough

1. Client initiates a connection to the server
2. Both parties perform a Roast handshake:
   - Generate and exchange signed hello messages
   - Verify signatures and validate peer identities using AWS STS
   - Confirm peer roles are allowed to connect
3. Upon successful handshake, each side generates their ephemeral certificates
4. A standard Go `crypto/tls` handshake is performed using these certificates
5. TLS channel is established for application data and the `net.Conn` is
   returned for the caller to use

## SigV4 + GetCallerIdentity == `Sign(🥳)`

AWS's primary authentication mechanism (SigV4) is one of the most robust pieces
of authentication technology in widespread use today. As an authentication
mechanism, it provides significantly more than a simple identity tokens (a.k.a.
Bearer Tokens). It ensures that AWS can validate not only which identity sent
the request, but also the integrity of the entire request, including the HTTP
method, chosen headers, and body.

AWS has an API called `GetCallerIdentity` which allows anyone with AWS
Credentials to ask "Who am I?". This is normally used by humans for debugging.

However, we can combine these two together by:

- Constructing a GetCallerIdentity request with a body containing the arbitrary
  bytes we want to "sign"
- Using an AWS SDK and available AWS credentials to generate a signature for
  this request

The signature guarantees both the sender's AWS identity and the integrity of the
message. This means we can pass this "signed request" to anyone else who can
make a network request to AWS, and they can verify it came from "us" and that no
one has tampered with the data we're sharing.

This approach turns AWS credentials into a generic bytes signing method,
allowing integrity-assured and authenticated message exchange without
introducing additional "key distribution problems" beyond the one you've already
solved by using AWS's identity system.

## Connection Sequence Diagrams

### Full Setup Sequence

This is a high level diagram showing a summarized description of the Roast
connection setup sequence.

```mermaid
sequenceDiagram
    participant C as Client
    participant S as Server

    rect rgb(70, 130, 180)
        Note over C,S: Roast Authentication Protocol
        
        C->>S: ClientHello

        Note over S: Verify ClientHello with AWS STS
        
        S->>C: ServerHello

        Note over C: Verify ServerHello with AWS STS
    end

    Note over C,S: Normal mTLS with<br/>exchanged certs
    
    Note over C,S: Application data<br/>over authenticated mTLS
```

### Roast Handshake Detail

This diagram provides a step-by-step walkthrough of the Roast handshake.

```mermaid
sequenceDiagram
    participant C as Client  
    participant S as Server
    participant AWS as AWS STS

    C<<->>S: TCP Connection Establishment

    rect rgb(70, 130, 180)
        Note left of C: Roast mutual authentication
        
        C->>C: Generate an ephemeral CA
        C->>C: SigV4Sign(ClientHello, ClientIdentity)
        C->>S: SignedClientHello
        
        rect rgb(205, 133, 63)
            Note left of S: ClientHello verification
            S->>AWS: SigV4Verify(SignedClientHello)
            AWS-->>S: ClientIdentity
            S->>S: Verify ClientIdentity is an allowed peer
        end
        
        S->>S: Generate an ephemeral CA
        S->>S: SigV4Sign(ServerHello, ServerIdentity)
        S->>C: SignedServerHello
        
        rect rgb(60, 179, 113)
            Note left of C: ServerHello verification
            C->>AWS: SigV4Verify(SignedServerHello)
            AWS-->>C: ServerIdentity
            C->>C: Verify ServerIdentity is an allowed peer
        end
    end

    rect rgb(147, 112, 219)
        par Generate certs
            C->>C: Generate TLS Cert signed by local CA
            S->>S: Generate TLS Cert signed by local CA
        end
        C->>S: TLS ClientHello
        S->>C: TLS ServerHello
    end

    Note over C,S: Application data<br/>over authenticated mTLS
```
