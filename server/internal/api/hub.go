package api

import (
	"context"
	"sync"
	"time"
)

// Hub fans out "something changed in vault V" hints to long-pollers and
// WebSocket subscribers. It carries no data; subscribers re-query.
type Hub struct {
	mu     sync.Mutex
	vaults map[string]*vaultHub
}

type vaultHub struct {
	seq     int64
	epoch   int64
	waiters map[chan struct{}]struct{}
}

type Hint struct {
	Seq   int64 `json:"seq"`
	Epoch int64 `json:"epoch"`
}

func NewHub() *Hub { return &Hub{vaults: map[string]*vaultHub{}} }

func (h *Hub) get(vault string) *vaultHub {
	vh, ok := h.vaults[vault]
	if !ok {
		vh = &vaultHub{waiters: map[chan struct{}]struct{}{}}
		h.vaults[vault] = vh
	}
	return vh
}

// Publish records the latest seq/epoch and wakes every waiter.
func (h *Hub) Publish(vault string, seq, epoch int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	vh := h.get(vault)
	if seq > vh.seq {
		vh.seq = seq
	}
	if epoch > vh.epoch {
		vh.epoch = epoch
	}
	for ch := range vh.waiters {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Subscribe returns a channel that receives a tick on every publish, and an
// unsubscribe function.
func (h *Hub) Subscribe(vault string) (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	h.mu.Lock()
	vh := h.get(vault)
	vh.waiters[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(vh.waiters, ch)
		h.mu.Unlock()
	}
}

// Wait blocks until a publish happens, the timeout elapses, or ctx is done.
// Returns true if woken by a publish.
func (h *Hub) Wait(ctx context.Context, vault string, timeout time.Duration) bool {
	ch, unsub := h.Subscribe(vault)
	defer unsub()
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-ch:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// Current returns the last published seq/epoch (0 if nothing yet).
func (h *Hub) Current(vault string) Hint {
	h.mu.Lock()
	defer h.mu.Unlock()
	vh := h.get(vault)
	return Hint{Seq: vh.seq, Epoch: vh.epoch}
}
