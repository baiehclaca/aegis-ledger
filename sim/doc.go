// Package sim drives the consensus core with a seeded logical clock.
// Delay, loss, reordering and partitions are chosen by math/rand/v2 from
// the seed. Signature bytes are not reproducible: ML-DSA signatures are
// hedged from the process DRBG, and the protocol does not branch on them.
// The delivery schedule is reproducible.
//
// A safety run may drop messages before the stabilisation tick. A
// liveness run does not. It may partition the network, and it flushes
// the partition at or before that tick. After the tick, delivery takes
// one tick and nothing is lost. Byzantine behaviour continues.
package sim
