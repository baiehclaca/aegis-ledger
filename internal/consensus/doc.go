// Package consensus is the HotStuff-2 replica. It is a pure state
// machine: every input is an argument, every output is a return value,
// and time, storage, and the network stay behind the caller.
//
// The caller delivers messages and reports that a timer fired. The
// replica returns the messages to send, the blocks that became final,
// and the next timer. It does not open sockets, read a clock, or write
// a disk itself. internal/store implements Store with an fsync before
// the call returns, which is what makes a vote durable.
package consensus
