package roast_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"slices"
	"testing"

	"github.com/thomasdesr/roast/internal/errorutil"
	"github.com/thomasdesr/roast/internal/testutils"
	"golang.org/x/sync/errgroup"
)

func TestEnsureNoClearTextOnTheWire(t *testing.T) {
	rl, rd := localValidListenerAndDialer(t)

	left, right := testutils.ConnPipe(t)

	left = &testutils.RecordingConn{Conn: left}
	right = &testutils.RecordingConn{Conn: right}

	// Testing infra setup, now we can run an upgrade from both sides and send some data through
	var g errgroup.Group
	g.Go(func() error { // Server is gonna be an echo server
		tlsConn, _, err := rl.UpgradeServerConn(context.Background(), right)
		if err != nil {
			return errorutil.Wrap(err, "failed to upgrade server conn")
		}
		defer tlsConn.Close()

		// Be an server on the server side
		_, err = io.Copy(tlsConn, tlsConn)

		return err
	})

	const CLEARTEXT = "Hello World! I am some unencrypted data, I shouldn't show up."
	g.Go(func() error {
		tlsConn, _, err := rd.UpgradeClientConn(context.Background(), left)
		if err != nil {
			return errorutil.Wrap(err, "failed to upgrade client conn")
		}
		defer tlsConn.Close()

		if _, err := fmt.Fprintln(tlsConn, CLEARTEXT); err != nil {
			return errorutil.Wrap(err, "failed to write to client conn")
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}

	// With the round trip complete, ensure that neither side's raw connection ever saw our "CLEARTEXT"

	leftTestConn := left.(*testutils.RecordingConn)
	rightTestConn := right.(*testutils.RecordingConn)

	// Note: This will actually duplicate all the data twice sicne its on both
	// the Send and recieve sides, but that's fine.
	allDataOnTheWire := slices.Concat(
		leftTestConn.DataRecv,
		leftTestConn.DataSent,
		rightTestConn.DataRecv,
		rightTestConn.DataSent,
	)

	if bytes.Contains(allDataOnTheWire, []byte(CLEARTEXT)) {
		t.Fatal("clear text found on the wire. Turn on NETDEBUG=1 to observe where")
	}

	t.Log("success")
}
