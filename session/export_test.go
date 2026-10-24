package session

// MemoryCheckpointsForTest borrows retained buffers for lifetime/clearing tests.
// Call only while the Memory is quiescent, and never modify these references.
func MemoryCheckpointsForTest(m *Memory, scope Scope, id ID) map[int][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	checkpoints := make(map[int][]byte)
	for key, checkpoint := range m.checkpoints {
		if key.Scope == scope && key.ID == id {
			checkpoints[key.Round] = checkpoint
		}
	}
	return checkpoints
}
