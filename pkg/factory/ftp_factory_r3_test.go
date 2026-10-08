package factory

// Fix round 3 (WF24, constitution 11.4.276): the reviewer's factory probes, adopted, and the killers of the surviving
// factory mutant NM06. TestWF24_N_PinStoreCapturedAtCreation asserted the DEFECT (a pin store installed after CreateClient
// and before Connect was ignored); here it asserts the corrected behaviour (it FAILS on the committed code 83c0ac1).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"digital.vasic.filesystem/pkg/client"
	"digital.vasic.filesystem/pkg/decorators"
	"digital.vasic.filesystem/pkg/ftp"
)

func TestWF24_R_F16_FactoryBuildsTheScanClient(t *testing.T) {
	withPinStore(t, ftp.NewMemPinStore())
	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "127.0.0.1", "port": 1, "credential_ref": "x"}})
	require.NoError(t, err)
	_, seek := c.(client.SeekableClient)
	merr := c.CreateDirectory(context.Background(), "x")
	cfgText := fmt.Sprintf("%+v", c.GetConfig())
	_, perr := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "password": "s3cret"}})
	t.Logf("CLOSED-F16 (factory part): type=%T seekable=%v mutation=%v config=%s inline-password=%v", c, seek, merr, cfgText, perr)
	require.True(t, seek)
	require.ErrorIs(t, merr, decorators.ErrReadOnly)
	require.Error(t, perr)
}

// The doc says DefaultPinStore must be set "before it connects": the factory no longer captures the variable at creation.
func TestWF24_N_PinStoreSetAfterCreation_IsUsedAtConnect(t *testing.T) {
	withPinStore(t, nil)
	c, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "127.0.0.1", "port": 1, "credential_ref": "x"}})
	require.NoError(t, err)
	ftp.DefaultPinStore = ftp.NewMemPinStore() // set after creation, before connect (restored by withPinStore's cleanup)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	t.Setenv("FTP_CRED_X_PASSWORD", "pw")
	cerr := c.Connect(ctx)
	require.Error(t, cerr, "nothing listens on port 1")
	assert.False(t, errors.Is(cerr, ftp.ErrNoPinStore), "the store installed before Connect must be the one consulted: %v", cerr)
}

// NM06: disable_epsv reaches the client (PublicConfig now shows it; the factory mutant that dropped it survived).
func TestR3_NM06_FTPFactory_DisableEPSVReachesTheClient(t *testing.T) {
	on, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "credential_ref": "r", "disable_epsv": true}})
	require.NoError(t, err)
	assert.Contains(t, fmt.Sprintf("%+v", on.GetConfig()), "DisableEPSV:true")
	off, err := NewDefaultFactory().CreateClient(&client.StorageConfig{Protocol: "ftp", Settings: map[string]interface{}{"host": "h", "credential_ref": "r"}})
	require.NoError(t, err)
	assert.Contains(t, fmt.Sprintf("%+v", off.GetConfig()), "DisableEPSV:false")
}
