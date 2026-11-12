// Package pacemaker advances views. It does not sign, and it does not
// read a clock: the caller reports that the current view's timer fired,
// and this package counts timeouts into a certificate and chooses the
// next timer interval.
package pacemaker
