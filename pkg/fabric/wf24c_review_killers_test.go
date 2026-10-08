// ADOPTED VERBATIM (constitution 11.4.276(D)) from the independent re-review WF24 (zz_wf24c_test.go); strengthenings, if any, are marked ADOPTED AS ASSERTION / ADAPTED.
package fabric_test

// WF24 killer probes: each PASSES on the committed code and must FAIL on the named surviving mutant,
// proving the mutant is NOT equivalent (the suite simply has no assertion for that behaviour).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/fabric"
)

// K11 (M11): the pool is closed while a borrower's probe runs and the borrower gives up: the probed
// connection must be disconnected, not put back into the closed pool.
type gateProbe struct {
	*poolClient
	started chan struct{}
	disc    *atomic.Int64
}

func (g *gateProbe) TestConnection(ctx context.Context) error {
	select {
	case g.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}
func (g *gateProbe) Disconnect(ctx context.Context) error {
	g.disc.Add(1)
	return g.poolClient.Disconnect(ctx)
}

type gateFactory struct {
	started chan struct{}
	disc    atomic.Int64
}

func (f *gateFactory) CreateClient(*client.StorageConfig) (client.Client, error) {
	k := newFk("p")
	k.connected = false
	return &gateProbe{poolClient: &poolClient{k}, started: f.started, disc: &f.disc}, nil
}
func (*gateFactory) SupportedProtocols() []string { return nil }

func TestK11_CloseDuringProbeDisconnectsTheProbedConnection(t *testing.T) {
	f := &gateFactory{started: make(chan struct{}, 1)}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 1, HealthTimeout: 10 * time.Second})
	c, err := p.GetClient(cfgFor("a")) // first borrow: new connection, no probe
	if err != nil {
		t.Fatal(err)
	}
	_ = p.ReturnClient(c)
	ctx, cancel := context.WithCancel(context.Background())
	res := make(chan error, 1)
	go func() { _, e := p.GetClientContext(ctx, cfgFor("a")); res <- e }()
	<-f.started
	_ = p.CloseAll()
	cancel()
	if e := <-res; !errors.Is(e, context.Canceled) {
		t.Fatalf("err=%v", e)
	}
	if f.disc.Load() != 1 || p.Stats().Idle != 0 {
		t.Errorf("DEFECT: the probed connection survived CloseAll (disconnects=%d idle=%d)", f.disc.Load(), p.Stats().Idle)
	}
}

// K13 (M13): unmarshalable settings get a fresh login after the settings CHANGE.
func TestK13_UnmarshalableSettingsChangeAllowsANewLogin(t *testing.T) {
	f := &slowFactory{connectErr: fabric.MarkAuth(errors.New("530 nope"))}
	p := newPool(t, f, fabric.PoolOptions{MaxPerKey: 2})
	a := cfgFor("a")
	a.Settings = map[string]interface{}{"opaque": make(chan int)} // json.Marshal fails
	_, _ = p.GetClient(a)
	b := cfgFor("a")
	b.Settings = map[string]interface{}{"opaque": make(chan int), "password": "changed"}
	_, _ = p.GetClient(b)
	if f.conn.Load() != 2 {
		t.Errorf("DEFECT: changed (unmarshalable) settings did not get a new login attempt: connects=%d", f.conn.Load())
	}
}

// K38 (M38): members of errors.Join are walked; a joined path wrapper is not auth evidence.
func TestK38_JoinedPathWrapperIsNotAuth(t *testing.T) {
	e := errors.Join(fmt.Errorf("open /m/Access Denied (2019).mkv: %w", syscall.ECONNRESET), errors.New("close: ok"))
	if got := fabric.Classify(e); got != fabric.ClassTransient {
		t.Errorf("DEFECT: %v", got)
	}
}

// K40 (M40): FTP 500 (syntax error) is permanent (RFC 959 5yz).
func TestK40_FTP500IsPermanent(t *testing.T) {
	if got := fabric.Classify(&textproto.Error{Code: 500, Msg: "Syntax error, command unrecognized"}); got != fabric.ClassPermanent {
		t.Errorf("DEFECT: 500 -> %v", got)
	}
}

// K51 (M51): ReadOnly passes a (nil, nil) stream through as nil.
type roNil struct{ *fk }

func (roNil) ReadFile(context.Context, string) (io.ReadCloser, error) { return nil, nil }

func TestK51_ReadOnlyNilStreamStaysNil(t *testing.T) {
	rc, err := decorators.ReadOnly(roNil{newFk("p")}).ReadFile(context.Background(), "/x")
	if rc != nil || err != nil {
		t.Errorf("DEFECT: ReadOnly turned (nil,nil) into (%T, %v)", rc, err)
	}
}

// K66 (M66): a caller whose deadline falls AFTER its start slot is served, not refused (false-refusal guard).
func TestK66_DeadlineAfterSlotIsServed(t *testing.T) {
	b := mustBudget(t, 2, 2, nil) // 500 ms spacing, real clock
	r1, err := b.Acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	r1()
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond) // slot at ~+500 ms
	defer cancel()
	r2, err := b.Acquire(ctx)
	if err != nil {
		t.Fatalf("DEFECT: a caller whose deadline (900ms) is after its slot (~500ms) was refused: %v", err)
	}
	r2()
}

// K69 (M69): free slots kept ascending so the cascade winds back through all of them.
func TestK69_CascadeAcrossOutOfOrderFrees(t *testing.T) {
	clk := newParkClock()
	b := mustBudget(t, 8, 10, clk)
	r1, _ := b.Acquire(context.Background()) // T+0
	defer r1()
	var cs []chan acqResult
	var cancels []context.CancelFunc
	for i := 1; i <= 3; i++ { // T+100, T+200, T+300
		ctx, cancel := context.WithCancel(context.Background())
		cs = append(cs, acquireAsync(b, ctx))
		cancels = append(cancels, cancel)
		clk.waitParked(t, i)
	}
	for _, i := range []int{1, 0, 2} { // free T+200, then T+100 (out of order), then the tail T+300
		cancels[i]()
		<-cs[i]
	}
	clk.waitParked(t, 0)
	clk.advance(150 * time.Millisecond)
	c := acquireAsync(b, context.Background())
	select {
	case r := <-c:
		if r.err != nil {
			t.Fatal(r.err)
		}
		r.rel()
	case <-time.After(300 * time.Millisecond):
		clk.advance(time.Second)
		if r := <-c; r.err == nil {
			r.rel()
		}
		t.Errorf("DEFECT: the caller waits for a slot nobody used (sleeps %v)", clk.sleeps())
	}
}
