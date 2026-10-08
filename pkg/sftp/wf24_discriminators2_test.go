package sftp

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// V07: a negative CancelGrace closes at once (guide: "negative: none").
func TestWF24D2_V07_NegativeGraceClosesAtOnce(t *testing.T) {
	rel := make(chan struct{})
	defer close(rel)
	s := startProbe(t, probeOpts{fileList: blockStatLister{release: rel}})
	_ = os.WriteFile(filepath.Join(s.Dir, "hang"), []byte("x"), 0o644)
	c := probeClient(s, func(cfg *Config) { cfg.CancelGrace = -1; cfg.MaxRetries = -1 })
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background()) //nolint:errcheck
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.GetFileInfo(ctx, "hang")
	el := time.Since(start)
	t.Logf("elapsed=%v err=%v", el, err)
	if el > 700*time.Millisecond {
		t.Errorf("negative CancelGrace still waited %v (a grace was applied)", el)
	}
}

type wfShortWriter struct{ n int }

func (w *wfShortWriter) Write(p []byte) (int, error) {
	w.n += len(p) / 2
	return len(p) / 2, nil
}

// V08: a writer that accepts fewer bytes than given is an io.ErrShortWrite, never a silent success.
func TestWF24D2_V08_RangedWriteToReportsShortWrite(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "f"), make([]byte, 100000), 0o644)
	c := probeClient(s, nil)
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background()) //nolint:errcheck
	r, err := c.ReadRange(context.Background(), "f", 0, 50000)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	w := &wfShortWriter{}
	_, err = r.(io.WriterTo).WriteTo(w)
	t.Logf("err=%v written=%d", err, w.n)
	if err != io.ErrShortWrite {
		t.Errorf("short write not reported: %v", err)
	}
}

// V09: Close of a file whose connection died is nil (the handle died with its connection).
func TestWF24D2_V09_CloseAfterDeathIsNil(t *testing.T) {
	s := startProbe(t, probeOpts{})
	_ = os.WriteFile(filepath.Join(s.Dir, "a.txt"), []byte("abc"), 0o644)
	c := probeClient(s, func(cfg *Config) { cfg.MaxRetries = -1 })
	if err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer c.Disconnect(context.Background()) //nolint:errcheck
	rc, err := c.ReadFile(context.Background(), "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	killConnAndWait(c)
	if err := rc.Close(); err != nil {
		t.Errorf("Close after connection death: %v", err)
	}
}
