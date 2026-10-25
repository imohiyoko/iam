package memory

// tamperAudit は監査ログの1件のペイロードを書き換える（テスト専用）。
func (m *Storage) tamperAudit(seq int64, payload []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s.audit[seq-1].rec.Payload = payload
}
