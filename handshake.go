package roast

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/internal/errorutil"
)

func clientHandshake(ctx context.Context, conn net.Conn, signer gcisigner.Signer, verifier gcisigner.Verifier) (*tls.Config, *PeerMetadata, error) {
	remoteHost, _, _ := strings.Cut(conn.RemoteAddr().String(), ":") // Trim off any port

	localCA, err := makeLocalCA()
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to make a local CA")
	}

	// Write our client hello
	{
		ch, err := json.Marshal(clientHello{
			ClientCA:        localCA.certPEM,
			ServerHostnames: []string{remoteHost},
		})
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to marshal client hello")
		}

		signedCH, err := signer.Sign(ctx, ch)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to sign client hello")
		}

		if err := json.NewEncoder(conn).Encode(signedCH); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to write client handshake")
		}
	}

	// Read the server hello
	var (
		sh   serverHello
		peer PeerMetadata
	)
	{
		var signedResponse gcisigner.UnverifiedMessage
		if err := json.NewDecoder(conn).Decode(&signedResponse); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to read server handshake")
		}

		verifiedResponse, err := verifier.Verify(ctx, &signedResponse)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to verify server hello")
		}

		if err := json.Unmarshal(verifiedResponse.Payload, &sh); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to unmarshal server hello")
		}

		peerARN, err := arn.Parse(verifiedResponse.CallerIdentity.Arn)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to parse peer ARN from a getcalleridentity response")
		}

		peer = PeerMetadata{
			AccountID: verifiedResponse.CallerIdentity.Account,
			Role:      peerARN,
		}
	}

	tlsConfig, err := makeClientConfig(*localCA, remoteHost, sh)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to make client config")
	}

	return tlsConfig, &peer, nil
}

func serverHandshake(ctx context.Context, conn net.Conn, signer gcisigner.Signer, verifier gcisigner.Verifier) (*tls.Config, *PeerMetadata, error) {
	// Read the client hello
	var (
		ch   clientHello
		peer PeerMetadata
	)
	{
		var unverifiedHandshake gcisigner.UnverifiedMessage
		if err := json.NewDecoder(conn).Decode(&unverifiedHandshake); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to read client handshake")
		}

		verifiedHandshake, err := verifier.Verify(ctx, &unverifiedHandshake)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to verify client hello")
		}

		if err := json.Unmarshal(verifiedHandshake.Payload, &ch); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to unmarshal client hello")
		}

		peerARN, err := arn.Parse(verifiedHandshake.CallerIdentity.Arn)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to parse peer ARN from a getcalleridentity response")
		}

		peer = PeerMetadata{
			AccountID: verifiedHandshake.CallerIdentity.Account,
			Role:      peerARN,
		}
	}

	localCA, err := makeLocalCA()
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to make a local CA")
	}

	// Write our server hello
	{
		sh, err := json.Marshal(serverHello{
			ServerCA: localCA.certPEM,
		})
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to marshal server hello")
		}

		signedSH, err := signer.Sign(ctx, sh)
		if err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to sign server hello")
		}

		if err := json.NewEncoder(conn).Encode(signedSH); err != nil {
			return nil, nil, errorutil.Wrap(err, "failed to write server handshake")
		}
	}

	tlsConfig, err := makeServerConfig(*localCA, ch)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to make server config")
	}

	return tlsConfig, &peer, nil
}
