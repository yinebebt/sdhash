package sdhash

import (
	"errors"
	"math/bits"
)

var bitMasks32 = []uint32{
	0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF,
	0x01FF, 0x03FF, 0x07FF, 0x0FFF, 0x1FFF, 0x3FFF, 0x7FFF, 0xFFFF,
	0x01FFFF, 0x03FFFF, 0x07FFFF, 0x0FFFFF, 0x1FFFFF, 0x3FFFFF, 0x7FFFFF, 0xFFFFFF,
	0x01FFFFFF, 0x03FFFFFF, 0x07FFFFFF, 0x0FFFFFFF, 0x1FFFFFFF, 0x3FFFFFFF, 0x7FFFFFFF, 0xFFFFFFFF,
}

type bloomFilter struct {
	buffer      []uint8 // bloom filter data
	hamming     uint32  // hamming weight of this filter
	bitMask     uint64  // bit mask derived from filter size
	maxElem     uint64  // maximum number of elements
	hashCount   uint16  // number of hash functions (k)
	bfElemCount uint64  // actual number of elements inserted
}

func newBloomFilter(size uint64, hashCount uint16, maxElem uint64) (*bloomFilter, error) {
	bf := &bloomFilter{
		hashCount: hashCount,
		maxElem:   maxElem,
	}

	// Size must be a power of 2 and at least 64.
	if size >= 64 && (size&(size-1)) == 0 {
		bf.bitMask = uint64(bitMasks32[bits.Len64(size)+1])
	} else {
		return nil, errors.New("bloom filter size must be a power of 2 and at least 64 bytes")
	}

	bf.buffer = make([]uint8, size)

	return bf, nil
}

// mustNewBloomFilter is like newBloomFilter but panics on error.
// Use it only when the size argument is a compile-time constant known to be
// a valid power of two ≥ 64 (e.g. bigFilter = 16384), making the error path
// unreachable.
func mustNewBloomFilter(size uint64, hashCount uint16, maxElem uint64) *bloomFilter {
	bf, err := newBloomFilter(size, hashCount, maxElem)
	if err != nil {
		panic(err)
	}
	return bf
}

func newBloomFilterFromExistingData(data []uint8, bfElemCount int) *bloomFilter {
	bf := &bloomFilter{
		bitMask:     uint64(bitMasks32[bits.Len(uint(len(data)))+1]),
		hashCount:   defaultHashCount,
		bfElemCount: uint64(bfElemCount),
		buffer:      make([]uint8, len(data)),
	}

	copy(bf.buffer, data)
	bf.computeHamming()

	return bf
}

func (bf *bloomFilter) fold(times uint32) {
	bfSize := len(bf.buffer)
	for i := uint32(0); i < times; i++ {
		for j := 0; j < bfSize/2; j++ {
			bf.buffer[j] |= bf.buffer[j+(bfSize/2)]
		}
		bfSize >>= 2
		if bfSize == 32 {
			break
		}
	}
	bf.buffer = bf.buffer[:bfSize]
	bf.bitMask = uint64(bitMasks32[bits.Len(uint(bfSize))+1])
}

func (bf *bloomFilter) computeHamming() {
	bf.hamming = 0
	for _, b := range bf.buffer {
		bf.hamming += uint32(bits.OnesCount8(b))
	}
}

// insertSha1 inserts a SHA1 hash into the bloom filter.
// Returns true if the element was new (i.e. at least one bit was not already set).
func (bf *bloomFilter) insertSha1(sha1 []uint32) bool {
	var pos, k uint32
	var bitCount uint16
	for i := uint16(0); i < bf.hashCount; i++ {
		pos = sha1[i] & uint32(bf.bitMask)
		k = pos >> 3
		if (bf.buffer[k] & bitPositions[pos&0x7]) != 0 {
			bitCount++
		} else {
			bf.buffer[k] |= bitPositions[pos&0x7]
		}
	}
	if bitCount < bf.hashCount {
		bf.bfElemCount++
		return true
	}
	return false
}

// bfSha1Insert inserts a SHA1 hash into a raw bloom filter buffer and returns the number of newly set bits.
func bfSha1Insert(bf []uint8, sha1Hash [5]uint32) uint32 {
	var insertCnt uint32
	for i := range sha1Hash {
		insert := sha1Hash[i] & defaultMask
		k := insert >> 3
		if bf[k]&bitPositions[insert&0x7] == 0 {
			insertCnt++
		}
		bf[k] |= bitPositions[insert&0x7]
	}
	return insertCnt
}

// andPopcount returns the number of bits set in the AND of two 256-byte bloom filters.
func andPopcount(bf1, bf2 []uint8) uint32 {
	var count uint32
	for i := 0; i < 256; i++ {
		count += uint32(bits.OnesCount8(bf1[i] & bf2[i]))
	}
	return count
}
