package memory

import (
	"testing"

	"github.com/imohiyoko/iam/adapters/storage/storagetest"
	"github.com/imohiyoko/iam/shared/clock"
	"github.com/imohiyoko/iam/shared/port"
)

func TestContract(t *testing.T) {
	storagetest.Run(t, storagetest.Harness{
		New: func(_ *testing.T, clk clock.Clock) port.Storage { return New(clk) },
		TamperAudit: func(_ *testing.T, s port.Storage, seq int64, payload []byte) {
			s.(*Storage).tamperAudit(seq, payload)
		},
	})
}
