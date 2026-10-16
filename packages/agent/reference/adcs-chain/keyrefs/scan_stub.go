//go:build !windows

// Unsupported hosts cannot authorize machine-key deletion from absent native metadata.
package keyrefs

func Scan(r Request) Result { return incomplete("unsupported_platform", Result{}) }
