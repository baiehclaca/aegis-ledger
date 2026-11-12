package consensus

import "errors"

// Errors from a replica that has stopped making sense of its own state,
// or from the store. A malformed message is not one of these: Step
// returns a nil error and Output.Dropped, and the replica keeps running.
var (
	ErrState     = errors.New("consensus: invalid local state")
	ErrStore     = errors.New("consensus: store")
	ErrQueueFull = errors.New("consensus: event queue is full")
)
