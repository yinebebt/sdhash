package sdhash

import (
	"fmt"
)

// SdbfFactory creates a Sdbf digest from a binary source.
// Use WithBlockSize to configure the factory before calling Compute.
//
// Factories are immutable: WithBlockSize returns a new factory rather than
// modifying the receiver, so all methods are inherently safe for concurrent use.
type SdbfFactory interface {

	// WithBlockSize sets the block size for block-aligned (dd) mode and returns
	// a new factory with that configuration applied. A value of 0 (the default)
	// produces a digest in stream mode.
	WithBlockSize(blockSize uint32) SdbfFactory

	// Compute runs the digesting process and returns the resulting Sdbf.
	Compute() (Sdbf, error)
}

type sdbfFactory struct {
	buffer      []uint8
	ddBlockSize uint32
}

// CreateSdbfFromBytes returns a factory that will produce a Sdbf from the given byte slice.
// The slice must be at least MinFileSize bytes.
func CreateSdbfFromBytes(buffer []uint8) (SdbfFactory, error) {
	if len(buffer) < MinFileSize {
		return nil, fmt.Errorf("buffer length must be at least %d bytes", MinFileSize)
	}
	return &sdbfFactory{
		buffer: buffer,
	}, nil
}

// WithBlockSize returns a new factory with the given block size configured.
// It does not modify the receiver.
func (sdf *sdbfFactory) WithBlockSize(blockSize uint32) SdbfFactory {
	return &sdbfFactory{
		buffer:      sdf.buffer,
		ddBlockSize: blockSize,
	}
}

func (sdf *sdbfFactory) Compute() (Sdbf, error) {
	return createSdbf(sdf.buffer, sdf.ddBlockSize)
}
