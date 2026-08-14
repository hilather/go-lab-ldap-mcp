// Package reset owns the exclusive mutation gate and suffix-scoped soft
// reset state machine. It must not control the container runtime and
// must not write the baseline marker (KD-R18).
package reset
