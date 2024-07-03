# Roast: mTLS on AWS without the hassle

AWS already offers an identity system, why deal with setting up a new one in the
form of CAs?

Wouldn't it be a lot simplier if all you had to do to get Mutually
Authenticating TLS (mTLS) protected connections was listing with which IAM Roles
a service expects as clients?

Roast is designed to let you use your existing identity system to make it
trivial to get mTLS connections setup based on your service's existing AWS
credentials.

TODO: Diagram + explanation of the overal design (gci handshake on first
contact, exchange certs, etc)

---

# WIP:

- [ ] Add HTTP examples
- [ ] Also use the security-token/ec2-instance creds to attach more useful
      metadata to the cert itself.
