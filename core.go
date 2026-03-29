package sdhash

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type bloomFilter struct {
	buffer    []uint8 // bloom filter data
	bitMask   uint64  // bit mask derived from filter size
	maxElem   uint64  // maximum number of elements
	hashCount uint16  // number of hash functions (k)
}

func newBloomFilter(size uint64, hashCount uint16, maxElem uint64) (*bloomFilter, error) {
	bf := &bloomFilter{
		hashCount: hashCount,
		maxElem:   maxElem,
	}

	// Size must be a power of 2 and at least 64.
	if size >= 64 && (size&(size-1)) == 0 {
		bf.bitMask = size*8 - 1
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
	return bitCount < bf.hashCount
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

// Configuration defaults for the sdbf algorithm. Each of these values is
// snapshotted into the sdbf struct at construction time; the package-level
// vars are never read during digest computation. It is therefore safe to
// update these defaults between constructions without any synchronization,
// and changing them has no effect on digests that are already in progress
// or complete.
var (
	BfSize         uint32 = 256    // BfSize is the size in bytes of each bloom filter.
	PopWinSize     uint32 = 64     // PopWinSize is the size of the sliding window used to hash input.
	MaxElem        uint32 = 160    // MaxElem is the maximum number of elements per bloom filter in stream mode.
	MaxElemDd      uint32 = 192    // MaxElemDd is the maximum number of elements per bloom filter in block mode.
	Threshold      uint32 = 16     // Threshold is the minimum score for a chunk position to be hashed.
	BlockSize             = 4 * kB // BlockSize is the block size used to generate chunk ranks.
	EntropyWinSize        = 64     // EntropyWinSize is the entropy window size used to generate chunk ranks.
)

const (
	// MinFileSize is the minimum input size (in bytes) required to compute a digest.
	MinFileSize = 512

	kB           = 1024
	mB           = kB * kB
	bins         = 1000
	entropyPower = 10
	entropyScale = bins * (1 << entropyPower)
	minElemCount = 16

	bigFilter     = 16384
	bigFilterElem = 8738

	magicStream = "sdbf"
	sdbfVersion = 3
	magicDD     = "sdbf-dd"

	defaultMask      = 0x7FF
	defaultHashCount = 5
)

var entropy64Ranks = []uint32{
	000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	101, 102, 106, 112, 108, 107, 103, 100, 109, 113, 128, 131, 141, 111, 146, 153, 148, 134, 145, 110,
	114, 116, 130, 124, 119, 105, 104, 118, 120, 132, 164, 180, 160, 229, 257, 211, 189, 154, 127, 115,
	129, 142, 138, 125, 136, 126, 155, 156, 172, 144, 158, 117, 203, 214, 221, 207, 201, 123, 122, 121,
	135, 140, 157, 150, 170, 387, 390, 365, 368, 341, 165, 166, 194, 174, 184, 133, 139, 137, 149, 173,
	162, 152, 159, 167, 190, 209, 238, 215, 222, 206, 205, 181, 176, 168, 147, 143, 169, 161, 249, 258,
	259, 254, 262, 217, 185, 186, 177, 183, 175, 188, 192, 195, 182, 151, 163, 199, 239, 265, 268, 242,
	204, 197, 193, 191, 218, 208, 171, 178, 241, 200, 236, 293, 301, 256, 260, 290, 240, 216, 237, 255,
	232, 233, 225, 210, 196, 179, 202, 212, 420, 429, 425, 421, 427, 250, 224, 234, 219, 230, 220, 269,
	247, 261, 235, 327, 332, 337, 342, 340, 252, 187, 223, 198, 245, 243, 263, 228, 248, 231, 275, 264,
	298, 310, 305, 309, 270, 266, 251, 244, 213, 227, 273, 284, 281, 318, 317, 267, 291, 278, 279, 303,
	452, 456, 453, 446, 450, 253, 226, 246, 271, 277, 295, 302, 299, 274, 276, 285, 292, 289, 272, 300,
	297, 286, 314, 311, 287, 283, 288, 280, 296, 304, 308, 282, 402, 404, 401, 415, 418, 313, 320, 307,
	315, 294, 306, 326, 321, 331, 336, 334, 316, 328, 322, 324, 325, 330, 329, 312, 319, 323, 352, 345,
	358, 373, 333, 346, 338, 351, 343, 405, 389, 396, 392, 411, 378, 350, 388, 407, 423, 419, 409, 395,
	353, 355, 428, 441, 449, 474, 475, 432, 457, 448, 435, 462, 470, 467, 468, 473, 426, 494, 487, 506,
	504, 517, 465, 459, 439, 472, 522, 520, 541, 540, 527, 482, 483, 476, 480, 721, 752, 751, 728, 730,
	490, 493, 495, 512, 536, 535, 515, 528, 518, 507, 513, 514, 529, 516, 498, 492, 519, 508, 544, 547,
	550, 546, 545, 511, 532, 543, 610, 612, 619, 649, 691, 561, 574, 591, 572, 553, 551, 565, 597, 593,
	580, 581, 642, 578, 573, 626, 696, 584, 585, 595, 590, 576, 579, 583, 605, 569, 560, 558, 570, 556,
	571, 656, 657, 622, 624, 631, 555, 566, 564, 562, 557, 582, 589, 603, 598, 604, 586, 577, 588, 613,
	615, 632, 658, 625, 609, 614, 592, 600, 606, 646, 660, 666, 679, 685, 640, 645, 675, 681, 672, 747,
	723, 722, 697, 686, 601, 647, 677, 741, 753, 750, 715, 707, 651, 638, 648, 662, 667, 670, 684, 674,
	693, 678, 664, 652, 663, 639, 680, 682, 698, 695, 702, 650, 676, 669, 665, 688, 687, 701, 700, 706,
	683, 718, 703, 713, 720, 716, 735, 719, 737, 726, 744, 736, 742, 740, 739, 731, 711, 725, 710, 704,
	708, 689, 729, 727, 738, 724, 733, 692, 659, 705, 654, 690, 655, 671, 628, 634, 621, 616, 630, 599,
	629, 611, 620, 607, 623, 618, 617, 635, 636, 641, 637, 633, 644, 653, 699, 694, 714, 734, 732, 746,
	749, 755, 745, 757, 756, 758, 759, 761, 763, 765, 767, 771, 773, 774, 775, 778, 782, 784, 786, 788,
	793, 794, 797, 798, 803, 804, 807, 809, 816, 818, 821, 823, 826, 828, 829, 834, 835, 839, 843, 846,
	850, 859, 868, 880, 885, 893, 898, 901, 904, 910, 911, 913, 916, 919, 922, 924, 930, 927, 931, 938,
	940, 937, 939, 941, 934, 936, 932, 933, 929, 928, 926, 925, 923, 921, 920, 918, 917, 915, 914, 912,
	909, 908, 907, 906, 900, 903, 902, 905, 896, 899, 897, 895, 891, 894, 892, 889, 883, 890, 888, 879,
	887, 886, 882, 878, 884, 877, 875, 872, 876, 870, 867, 874, 873, 871, 869, 881, 863, 865, 864, 860,
	853, 855, 852, 849, 857, 856, 862, 858, 861, 854, 851, 848, 847, 845, 844, 841, 840, 837, 836, 833,
	832, 831, 830, 827, 824, 825, 822, 820, 819, 817, 815, 812, 814, 810, 808, 806, 805, 799, 796, 795,
	790, 787, 785, 783, 781, 777, 776, 772, 770, 768, 769, 764, 762, 760, 754, 743, 717, 712, 668, 661,
	643, 627, 608, 594, 587, 568, 559, 552, 548, 542, 539, 537, 534, 533, 531, 525, 521, 510, 505, 497,
	496, 491, 486, 485, 478, 477, 466, 469, 463, 458, 460, 444, 440, 424, 433, 403, 410, 394, 393, 385,
	377, 379, 382, 383, 380, 384, 372, 370, 375, 366, 354, 363, 349, 357, 347, 364, 367, 359, 369, 360,
	374, 344, 376, 335, 371, 339, 361, 348, 356, 362, 381, 386, 391, 397, 399, 398, 412, 408, 414, 422,
	416, 430, 417, 434, 400, 436, 437, 438, 442, 443, 447, 406, 451, 413, 454, 431, 455, 445, 461, 464,
	471, 479, 481, 484, 489, 488, 499, 500, 509, 530, 523, 538, 526, 549, 554, 563, 602, 596, 673, 567,
	748, 575, 766, 709, 779, 780, 789, 813, 811, 838, 842, 866, 942, 935, 944, 943, 947, 952, 951, 955,
	954, 957, 960, 959, 967, 966, 969, 962, 968, 953, 972, 961, 982, 979, 978, 981, 980, 990, 987, 988,
	984, 983, 989, 985, 986, 977, 976, 975, 973, 974, 970, 971, 965, 964, 963, 956, 958, 524, 950, 948,
	949, 945, 946, 800, 801, 802, 791, 792, 501, 502, 503, 000, 000, 000, 000, 000, 000, 000, 000, 000,
	000,
}

var cutoffs256 = []uint32{
	1250, 1250, 1250, 1250, 1006, 806, 650, 534, 442, 374, 319, 273, 240, 210, 184, 166,
	148, 132, 121, 110, 100, 93, 85, 78, 72, 67, 63, 59, 55, 52, 48, 45,
	43, 40, 38, 37, 35, 32, 31, 30, 28, 27, 26, 25, 24, 23, 22, 21, 20,
	19, 19, 18, 18, 17, 16, 15, 15, 15, 15, 14, 13, 13, 12, 12, 12, 12, 12, 11, 11,
	10, 10, 10, 10, 10, 10, 9, 9, 9, 9, 9, 9, 9, 8, 8, 8, 8, 8, 7, 7,
	7, 7, 7, 7, 7, 7, 6, 6, 6, 6, 6, 6, 6, 5, 5, 5, 5, 5, 5, 5,
	4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 3,
	3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2,
}

var bitPositions = []uint8{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}

var entropy64Int [65]uint64

func init() {
	// Precompute scaled entropy contributions for each possible byte-frequency count.
	for i := 1; i <= 64; i++ {
		p := float64(i) / 64
		entropy64Int[i] = uint64((-p * math.Log2(p) / 6) * entropyScale)
	}
}

// entropy64InitInt performs a full entropy computation for a 64-byte buffer.
func entropy64InitInt(buffer []uint8, ascii []uint8) uint64 {
	clear(ascii)
	for i := 0; i < 64; i++ {
		ascii[buffer[i]]++
	}
	var entropy uint64
	for i := 0; i < 256; i++ {
		if ascii[i] > 0 {
			entropy += entropy64Int[ascii[i]]
		}
	}
	return entropy
}

// entropy64IncInt performs an incremental (rolling) entropy update for a 64-byte window.
func entropy64IncInt(prevEntropy uint64, buffer []uint8, ascii []uint8) uint64 {
	if buffer[0] == buffer[64] {
		return prevEntropy
	}

	oldCharCnt := ascii[buffer[0]]
	newCharCnt := ascii[buffer[64]]

	ascii[buffer[0]]--
	ascii[buffer[64]]++

	if oldCharCnt == newCharCnt+1 {
		return prevEntropy
	}

	oldDiff := int64(entropy64Int[oldCharCnt]) - int64(entropy64Int[oldCharCnt-1])
	newDiff := int64(entropy64Int[newCharCnt+1]) - int64(entropy64Int[newCharCnt])

	entropy := int64(prevEntropy) - oldDiff + newDiff
	if entropy < 0 {
		entropy = 0
	} else if entropy > entropyScale {
		entropy = entropyScale
	}

	return uint64(entropy)
}

// u32sha1 computes the SHA1 of data and returns it as five little-endian uint32 values.
func u32sha1(data []uint8) [5]uint32 {
	sum := sha1.Sum(data)

	var buf [5]uint32
	for i := range buf {
		buf[i] = binary.LittleEndian.Uint32(sum[i*4 : (i+1)*4])
	}

	return buf
}

// chunkSlicePool reuses []uint16 backing arrays across generateChunkRanks /
// generateChunkScores calls to eliminate the dominant make() + GC overhead.
var chunkSlicePool = sync.Pool{
	New: func() any {
		return (*[]uint16)(nil)
	},
}

// getChunkSlice returns a zeroed []uint16 of the given length, reusing a
// pooled backing array when one of sufficient capacity is available.
func getChunkSlice(size int) []uint16 {
	if v := chunkSlicePool.Get(); v != nil {
		if sp := v.(*[]uint16); sp != nil && cap(*sp) >= size {
			s := (*sp)[:size]
			clear(s)
			return s
		}
	}
	return make([]uint16, size)
}

// putChunkSlice returns a slice to the pool for reuse. The caller must not
// retain any reference to the slice after this call.
func putChunkSlice(s []uint16) {
	chunkSlicePool.Put(&s)
}

// asciiPool reuses the 256-byte frequency table used by generateChunkRanks.
// The allocation is small but called per-chunk, so pooling it reduces GC scan
// pressure on high-throughput workloads.
var asciiPool = sync.Pool{
	New: func() any {
		buf := new([]uint8)
		*buf = make([]uint8, 256)
		return buf
	},
}

// generateChunkRanks generates entropy-based ranks for each position in fileBuffer.
//
// OPTIMIZATION HISTORY: Re-slicing chunkRanks at function entry to hint
// bounds check elimination (BCE) was attempted and had no effect. The compiler
// cannot eliminate the chunkRanks[offset] check because offset is bounded by
// a computed limit, not by len(chunkRanks) directly. The access pattern is
// already O(n) and the per-element cost is dominated by the entropy table
// lookup and the incremental entropy update, not by bounds checks.
func (sd *sdbf) generateChunkRanks(fileBuffer []uint8, chunkRanks []uint16) {
	var entropy uint64
	asciiPtr := asciiPool.Get().(*[]uint8)
	ascii := *asciiPtr
	clear(ascii)
	defer asciiPool.Put(asciiPtr)

	limit := len(fileBuffer) - sd.entropyWinSize
	for offset := 0; offset < limit; offset++ {
		if offset%sd.blockSize == 0 { // full entropy recalculation at block boundaries
			entropy = entropy64InitInt(fileBuffer[offset:], ascii)
		} else { // incremental rolling update
			entropy = entropy64IncInt(entropy, fileBuffer[offset-1:], ascii)
		}
		chunkRanks[offset] = uint16(entropy64Ranks[entropy>>entropyPower])
	}
}

// generateChunkScores generates scores for each position in a ranked chunk
// using a sliding minimum window.
//
// OPTIMIZATION HISTORY: This function is 50% of total CPU time. Three
// approaches to reduce that cost were evaluated and all failed:
//
//  1. BCE via re-slicing inputs at function entry: no effect. The compiler
//     cannot prove i+popWin < chunkSize because popWin is a runtime value.
//
//  2. BCE via range over sub-slices in the j-loop: reduced check count for
//     that loop but had no measurable effect on runtime. The hot checks —
//     chunkRanks[i+popWin] in the inner while-loop and chunkRanks[minPos] /
//     chunkScores[minPos] — are structurally unreachable by BCE because
//     minPos is assigned inside loop bodies and i mutates inside the inner
//     while body.
//
//  3. Algorithmic replacement with a monotonic deque O(n) sliding window
//     minimum: ruled out. The original algorithm is not a pure sliding
//     window minimum — the inner while-loop reuses the previous window's
//     minPos and scores it incrementally, producing different minPos
//     assignments than a deque. The corpus tests (digest-exact match against
//     C++ reference) would fail. Additionally, the algorithm is already
//     O(n) amortized on real entropy data because the inner while
//     fast-forwards i until the minimum expires.
//
// INSTRUCTION-LEVEL PROFILING (pprof Source view) confirmed the remaining
// cost is irreducible algorithmic work. 81% of this function's flat time
// (470s of 580s) is in the j-loop: the for-j iteration, the two rank
// comparisons, and the equality branch. The flat-to-cum gap per line is
// 1–5%, meaning almost no time is spent in bounds-check panic paths. Even
// total elimination of bounds checks would save at most ~5% of this function.
//
// This is the performance floor. Parallelism at the file level (already
// implemented) is the correct lever for throughput.
func (sd *sdbf) generateChunkScores(chunkRanks []uint16, chunkSize uint64, chunkScores []uint16, scoreHistogram []int32) {
	popWin := uint64(sd.popWinSize)
	var minPos uint64
	minRank := chunkRanks[minPos]

	for i := uint64(0); chunkSize > popWin && i < chunkSize-popWin; i++ {
		if i > 0 && minRank > 0 {
			for chunkRanks[i+popWin] >= minRank && i < minPos && i < chunkSize-popWin+1 {
				if chunkRanks[i+popWin] == minRank {
					minPos = i + popWin
				}
				chunkScores[minPos]++
				i++
			}
		}
		minPos = i
		minRank = chunkRanks[minPos]
		for j := i + 1; j < i+popWin; j++ {
			if chunkRanks[j] < minRank && chunkRanks[j] > 0 {
				minRank = chunkRanks[j]
				minPos = j
			} else if minPos == j-1 && chunkRanks[j] == minRank {
				minPos = j
			}
		}
		if chunkRanks[minPos] > 0 {
			chunkScores[minPos]++
		}
	}
	if scoreHistogram != nil {
		for i := uint64(0); i < chunkSize-popWin; i++ {
			scoreHistogram[chunkScores[i]]++
		}
	}
}

// generateChunkHash hashes high-scoring positions in fileBuffer and inserts them into the sdbf (stream mode).
//
// NOTE: Do not attempt to parallelize the SHA1 loop below or pipeline the
// hash insertions. This was evaluated and produced no measurable throughput
// gain. The reason is structural: when a multi-worker pool is already
// processing multiple inputs concurrently, the cores stay saturated at the
// file level. Adding within-file parallelism introduces synchronization
// overhead on the bloom filter and bigFilter state without freeing any CPU
// capacity. The sequential loop is the correct design.
//
// PROFILING NOTE: SHA1 accounts for roughly 1–5% of total CPU time
// depending on hardware. The dominant cost is generateChunkScores (50–62%).
// Slice zeroing (memclr from pooled slice reuse) varies from 7% on fast
// desktop cores to 25% on many-core servers. Optimizing SHA1 would have
// negligible impact on overall throughput.
func (sd *sdbf) generateChunkHash(fileBuffer []uint8, chunkPos uint64, chunkScores []uint16, chunkSize uint64) {
	bfCount := sd.bfCount
	lastCount := sd.lastCount
	currBf := sd.buffer[(bfCount-1)*sd.bfSize:]
	currentBigFilter := sd.bigFilters[len(sd.bigFilters)-1]
	var bigFilterElemCount uint64

	if chunkSize > uint64(sd.popWinSize) {
		for i := uint64(0); i < chunkSize-uint64(sd.popWinSize); i++ {
			if uint32(chunkScores[i]) > sd.threshold {
				sha1Hash := u32sha1(fileBuffer[chunkPos+i : chunkPos+i+uint64(sd.popWinSize)])

				// Skip if no new bits were set (repetitive feature).
				if bfSha1Insert(currBf, sha1Hash) == 0 {
					continue
				}

				// Skip if already seen in the large-scale deduplication filter.
				if !currentBigFilter.insertSha1(sha1Hash[:]) {
					continue
				}

				lastCount++
				bigFilterElemCount++
				if lastCount == sd.maxElem {
					currBf = currBf[sd.bfSize:]
					bfCount++
					lastCount = 0
				}
				if bigFilterElemCount == currentBigFilter.maxElem {
					currentBigFilter = mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)
					sd.bigFilters = append(sd.bigFilters, currentBigFilter)
					bigFilterElemCount = 0
				}
			}
		}
	}

	sd.bfCount = bfCount
	sd.lastCount = lastCount
}

// generateBlockHash hashes high-scoring positions in fileBuffer and inserts them into the sdbf (block mode).
func (sd *sdbf) generateBlockHash(fileBuffer []uint8, blockNum uint64, chunkScores []uint16, rem uint32,
	threshold uint32, allowed int32) {
	var hashCnt uint32
	maxOffset := sd.ddBlockSize
	if rem > 0 {
		maxOffset = rem
	}
	for i := uint32(0); i < maxOffset-sd.popWinSize && hashCnt < sd.maxElem; i++ {
		if uint32(chunkScores[i]) > threshold || (uint32(chunkScores[i]) == threshold && allowed > 0) {
			sha1Hash := u32sha1(fileBuffer[i : i+sd.popWinSize])
			bf := sd.buffer[blockNum*uint64(sd.bfSize) : (blockNum+1)*uint64(sd.bfSize)]
			if bfSha1Insert(bf, sha1Hash) == 0 { // skip repetitive features
				continue
			}
			hashCnt++
			if uint32(chunkScores[i]) == threshold {
				allowed--
			}
		}
	}

	sd.elemCounts[blockNum] = uint16(hashCnt)
}

// generateChunkSdbf computes the sdbf hash for a buffer in stream mode.
//
// For files spanning more than one chunk the work is split into two phases:
//
//   - Phase 1 (parallel): generateChunkRanks and generateChunkScores are
//     pure functions with no shared state, so they are dispatched concurrently
//     across chunks, bounded by runtime.NumCPU() goroutines. Each goroutine
//     operates on its own independent ranks and scores arrays; there is no
//     sharing between chunks.
//
//   - Phase 2 (sequential): generateChunkHash is called in strict chunk order
//     (0, 1, 2, … qt, rem). This preserves the cross-chunk bigFilter
//     deduplication behavior exactly — a feature seen in chunk N is still
//     rejected in chunk N+1, identical to the original sequential loop.
//
// Files that fit in a single chunk skip the parallel machinery entirely and
// follow the original sequential path.
func (sd *sdbf) generateChunkSdbf(fileBuffer []uint8, chunkSize uint64) {
	if chunkSize <= uint64(sd.popWinSize) {
		panic(fmt.Sprintf("chunkSize %d must be greater than popWinSize %d", chunkSize, sd.popWinSize))
	}

	fileSize := uint64(len(fileBuffer))
	buffSize := ((fileSize >> 11) + 1) << 8 // initial sdbf buffer estimate
	sd.buffer = make([]uint8, buffSize)

	qt := fileSize / chunkSize
	rem := fileSize % chunkSize

	totalChunks := qt
	if rem > 0 {
		totalChunks++
	}

	// Single-chunk fast path: skip parallel overhead entirely.
	if totalChunks <= 1 {
		chunkRanks := getChunkSlice(int(chunkSize))
		defer putChunkSlice(chunkRanks)
		chunkScores := getChunkSlice(int(chunkSize))
		defer putChunkSlice(chunkScores)

		if qt == 1 {
			sd.generateChunkRanks(fileBuffer[:chunkSize], chunkRanks)
			sd.generateChunkScores(chunkRanks, chunkSize, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, 0, chunkScores, chunkSize)
		} else if rem > 0 {
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], chunkRanks)
			sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
			sd.generateChunkHash(fileBuffer, qt*chunkSize, chunkScores, rem)
		}

		if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
			sd.bfCount--
			sd.lastCount = sd.maxElem
		}
		if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
			sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
		}
		return
	}

	// Multi-chunk path.

	// chunkWork holds the pre-computed scores and the effective size for one chunk.
	type chunkWork struct {
		scores []uint16
		size   uint64
	}
	results := make([]chunkWork, totalChunks)

	// Phase 1: parallel rank and score computation.
	// A buffered semaphore limits concurrency to runtime.NumCPU() goroutines.
	sem := make(chan struct{}, runtime.NumCPU())
	var wg sync.WaitGroup

	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx uint64) {
			defer wg.Done()
			defer func() { <-sem }()
			ranks := getChunkSlice(int(chunkSize))
			scores := getChunkSlice(int(chunkSize))
			sd.generateChunkRanks(fileBuffer[chunkSize*idx:chunkSize*(idx+1)], ranks)
			sd.generateChunkScores(ranks, chunkSize, scores, nil)
			putChunkSlice(ranks)
			results[idx] = chunkWork{scores: scores, size: chunkSize}
		}(i)
	}
	if rem > 0 {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			// Allocate ranks at full chunkSize so the slice is always large
			// enough regardless of rem; generateChunkRanks only writes up to
			// len(fileBuffer)-entropyWinSize entries.
			ranks := getChunkSlice(int(chunkSize))
			scores := getChunkSlice(int(chunkSize))
			sd.generateChunkRanks(fileBuffer[qt*chunkSize:], ranks)
			sd.generateChunkScores(ranks, rem, scores, nil)
			putChunkSlice(ranks)
			results[qt] = chunkWork{scores: scores, size: rem}
		}()
	}
	wg.Wait()

	// Phase 2: sequential hash insertion in original chunk order.
	// generateChunkHash is called in exactly the same order (0, 1, 2, … qt,
	// rem) as the original loop, so bigFilter cross-chunk deduplication is
	// preserved without any change to that function.
	var chunkPos uint64
	for i := uint64(0); i < totalChunks; i++ {
		r := results[i]
		sd.generateChunkHash(fileBuffer, chunkPos, r.scores, r.size)
		chunkPos += r.size
		putChunkSlice(r.scores)
	}

	// Drop the last filter if its membership is too low (reduces false positives).
	if sd.bfCount > 1 && sd.lastCount < sd.maxElem/8 {
		sd.bfCount--
		sd.lastCount = sd.maxElem
	}

	// Trim the buffer to the actual used size.
	if uint64(sd.bfCount)*uint64(sd.bfSize) < buffSize {
		sd.buffer = sd.buffer[:sd.bfCount*sd.bfSize]
	}
}

// generateSingleBlockSdbf is the goroutine worker for parallel block hash generation.
func (sd *sdbf) generateSingleBlockSdbf(fileBuffer []uint8, blockNum uint64) {
	blockSize := uint64(sd.ddBlockSize)
	var sum, allowed uint32
	var scoreHistogram [66]int32
	chunkRanks := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkRanks)
	chunkScores := getChunkSlice(int(blockSize))
	defer putChunkSlice(chunkScores)

	sd.generateChunkRanks(fileBuffer, chunkRanks)
	sd.generateChunkScores(chunkRanks, blockSize, chunkScores, scoreHistogram[:])
	var k uint32
	for k = 65; k >= sd.threshold; k-- {
		if sum <= sd.maxElem && (sum+uint32(scoreHistogram[k]) > sd.maxElem) {
			break
		}
		sum += uint32(scoreHistogram[k])
	}
	allowed = sd.maxElem - sum
	sd.generateBlockHash(fileBuffer, blockNum, chunkScores, 0, k, int32(allowed))
}

// generateBlockSdbf computes the sdbf hash for a buffer in block-aligned (dd) mode.
func (sd *sdbf) generateBlockSdbf(fileBuffer []uint8) {
	blockSize := uint64(sd.ddBlockSize)
	qt := uint64(len(fileBuffer)) / blockSize
	rem := uint64(len(fileBuffer)) % blockSize

	var wg sync.WaitGroup
	for i := uint64(0); i < qt; i++ {
		wg.Add(1)
		go func(idx uint64) {
			defer wg.Done()
			sd.generateSingleBlockSdbf(fileBuffer[blockSize*idx:blockSize*(idx+1)], idx)
		}(i)
	}
	wg.Wait()

	if rem >= MinFileSize {
		chunkRanks := getChunkSlice(int(blockSize))
		defer putChunkSlice(chunkRanks)
		chunkScores := getChunkSlice(int(blockSize))
		defer putChunkSlice(chunkScores)

		remBuffer := fileBuffer[blockSize*qt : blockSize*qt+rem]
		sd.generateChunkRanks(remBuffer, chunkRanks)
		sd.generateChunkScores(chunkRanks, rem, chunkScores, nil)
		sd.generateBlockHash(remBuffer, qt, chunkScores, uint32(rem), sd.threshold, int32(sd.maxElem))
	}
}

// sdbfScore calculates the similarity score (0–100) between two sdbf digests.
// Both digests must have their hamming weights pre-computed (guaranteed after construction).
// The caller must hold at least read locks on both sdbf1 and sdbf2.
func sdbfScore(sdbf1 *sdbf, sdbf2 *sdbf, sample uint32) int {
	bfCount1 := sdbf1.bfCount
	if sample > 0 && bfCount1 > sample {
		bfCount1 = sample
	}

	// Always iterate over the smaller digest. This minimizes the number of
	// sdbfMaxScore calls while still finding the best match for every filter
	// in the smaller digest against the full larger digest.
	if bfCount1 > sdbf2.bfCount {
		sdbf1, sdbf2 = sdbf2, sdbf1
		bfCount1 = sdbf1.bfCount
	}

	if bfCount1 == 0 {
		return -1
	}

	var scoreSum float64
	var sparseCount uint32
	for i := uint32(0); i < bfCount1; i++ {
		scoreSum += sdbfMaxScore(sdbf1, i, sdbf2)
		if sdbf1.elemCount(i) < minElemCount {
			sparseCount++
		}
	}

	denominator := bfCount1
	if bfCount1 > 1 {
		denominator -= sparseCount
	}
	if denominator == 0 {
		scoreSum--
	}

	if scoreSum < 0 {
		return -1
	}

	return int(math.Round(100.0 * scoreSum / float64(denominator)))
}

// sdbfMaxScore calculates the maximum match of a single reference filter against all target filters.
// Returns 0 if the reference filter has too few elements for a valid comparison, -1 if no target
// filter had enough elements to score against, or a value in [0.0, 1.0] otherwise.
// The caller must hold at least read locks on both refSdbf and targetSdbf.
func sdbfMaxScore(refSdbf *sdbf, refIndex uint32, targetSdbf *sdbf) float64 {
	var maxScore float64 = -1
	bfSize := refSdbf.bfSize

	s1 := refSdbf.elemCount(refIndex)
	if s1 < minElemCount {
		return 0
	}
	bf1 := refSdbf.buffer[refIndex*bfSize:]
	e1Cnt := refSdbf.hamming[refIndex]
	for i := uint32(0); i < targetSdbf.bfCount; i++ {
		bf2 := targetSdbf.buffer[i*bfSize:]
		s2 := targetSdbf.elemCount(i)
		if s2 < minElemCount {
			continue
		}
		e2Cnt := targetSdbf.hamming[i]
		maxEst := min(e1Cnt, e2Cnt)
		cutOff := cutoffs256[4096/(s1+s2)]
		var score float64
		match := andPopcount(bf1, bf2)
		if match > cutOff {
			score = float64(match-cutOff) / float64(uint32(maxEst)-cutOff)
		}
		if score > maxScore {
			maxScore = score
		}
	}

	return maxScore
}

// Sdbf represents the similarity digest of a file or byte buffer. Two Sdbf values
// can be compared to produce a score indicating how similar their source data is.
//
// All methods are safe for concurrent use by multiple goroutines.
type Sdbf interface {

	// Size returns the total byte size of the bloom filter data within this Sdbf.
	Size() uint64

	// InputSize returns the size of the original data this Sdbf was generated from.
	InputSize() uint64

	// FilterCount returns the number of bloom filters in this Sdbf.
	FilterCount() uint32

	// Compare returns a similarity score in [0, 100] between this Sdbf and other.
	// A score of 0 indicates very different data; 100 indicates identical data.
	Compare(other Sdbf) int

	// CompareSample returns a similarity score in [0, 100] using at most sample
	// bloom filters from each digest. Use 0 to disable sampling.
	CompareSample(other Sdbf, sample uint32) int

	// String returns the digest encoded as a string in the sdbf wire format.
	String() string

	// FeatureDensity returns the ratio of total unique features inserted across
	// all bloom filters to the original input size. A low value indicates the
	// digest is degenerate — the input was too repetitive, low-entropy, or small
	// to produce enough features for a meaningful similarity comparison. Callers
	// should check this value and treat digests below a corpus-appropriate
	// threshold as unreliable.
	FeatureDensity() float64
}

type sdbf struct {
	mu           sync.RWMutex   // protects all fields below for concurrent access
	hamming      []uint16       // hamming weight for each bloom filter; always set after construction
	buffer       []uint8        // concatenated bloom filter data
	maxElem      uint32         // max elements per filter (snapshotted from MaxElem or MaxElemDd)
	bigFilters   []*bloomFilter // large deduplication filters used during stream-mode digesting
	bfCount      uint32         // number of bloom filters
	bfSize       uint32         // bloom filter size in bytes (snapshotted from BfSize)
	lastCount    uint32         // element count in the final filter (stream mode only)
	elemCounts   []uint16       // per-filter element counts (block mode only)
	ddBlockSize  uint32         // block size in block mode
	origFileSize uint64         // size of the original input data

	// Configuration snapshotted from package-level defaults at construction time.
	// Using struct fields instead of globals during computation eliminates data races
	// when defaults are updated between constructions.
	popWinSize     uint32 // snapshotted from PopWinSize
	threshold      uint32 // snapshotted from Threshold
	blockSize      int    // snapshotted from BlockSize
	entropyWinSize int    // snapshotted from EntropyWinSize
}

// readField reads a colon-terminated field from r and returns the value without the delimiter.
func readField(r *bufio.Reader) (string, error) {
	s, err := r.ReadString(':')
	if err != nil {
		return "", err
	}
	return s[:len(s)-1], nil
}

// readUint64Field reads a colon-terminated field from r and parses it as a decimal uint64.
func readUint64Field(r *bufio.Reader) (uint64, error) {
	s, err := readField(r)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(s, 10, 64)
}

// skipField reads and discards a colon-terminated field from r.
func skipField(r *bufio.Reader) error {
	_, err := r.ReadBytes(':')
	return err
}

// ParseSdbfFromString decodes a Sdbf from a digest string in sdbf wire format.
func ParseSdbfFromString(digest string) (Sdbf, error) {
	r := bufio.NewReader(strings.NewReader(digest))

	sd := &sdbf{}

	magic, err := readField(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read magic: %w", err)
	}

	version, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}
	if version > sdbfVersion {
		return nil, errors.New("unsupported sdbf version")
	}

	if err = skipField(r); err != nil { // namelen (always "1")
		return nil, fmt.Errorf("failed to read name length: %w", err)
	}
	if err = skipField(r); err != nil { // name (always "-")
		return nil, fmt.Errorf("failed to read name: %w", err)
	}

	if sd.origFileSize, err = readUint64Field(r); err != nil {
		return nil, fmt.Errorf("failed to read original file size: %w", err)
	}

	if err = skipField(r); err != nil { // hash algorithm (always "sha1")
		return nil, fmt.Errorf("failed to read hash algorithm: %w", err)
	}

	bfSize, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bloom filter size: %w", err)
	}

	if err = skipField(r); err != nil { // hash count
		return nil, fmt.Errorf("failed to read hash count: %w", err)
	}
	if err = skipField(r); err != nil { // bit mask
		return nil, fmt.Errorf("failed to read bit mask: %w", err)
	}

	maxElem, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read max elements: %w", err)
	}

	bfCount, err := readUint64Field(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read bloom filter count: %w", err)
	}

	switch magic {
	case magicStream:
		lastCount, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read last count: %w", err)
		}
		// Buffer is base64-encoded and terminated by '\n' (or EOF if no trailing newline).
		encodedBuffer, _ := r.ReadString('\n')
		if len(encodedBuffer) > 0 && encodedBuffer[len(encodedBuffer)-1] == '\n' {
			encodedBuffer = encodedBuffer[:len(encodedBuffer)-1] // strip newline
		}
		if sd.buffer, err = base64.StdEncoding.DecodeString(encodedBuffer); err != nil {
			return nil, fmt.Errorf("failed to decode buffer: %w", err)
		}
		sd.lastCount = uint32(lastCount)

	case magicDD:
		ddBlockSize, err := readUint64Field(r)
		if err != nil {
			return nil, fmt.Errorf("failed to read block size: %w", err)
		}
		sd.elemCounts = make([]uint16, bfCount)
		sd.buffer = make([]uint8, bfCount*bfSize)
		for i := uint64(0); i < bfCount; i++ {
			elemStr, err := readField(r)
			if err != nil {
				return nil, fmt.Errorf("failed to read element count for filter %d: %w", i, err)
			}
			elem, err := strconv.ParseUint(elemStr, 16, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse element count for filter %d: %w", i, err)
			}
			sd.elemCounts[i] = uint16(elem)

			// Each block's base64 is delimited by ':' except the last, which ends at '\n' (or EOF).
			encodedBuffer, _ := r.ReadString(':')
			tmpBuffer, err := base64.StdEncoding.DecodeString(encodedBuffer[:len(encodedBuffer)-1])
			if err != nil {
				return nil, fmt.Errorf("failed to decode data for filter %d: %w", i, err)
			}
			copy(sd.buffer[i*bfSize:], tmpBuffer)
		}
		sd.ddBlockSize = uint32(ddBlockSize)

	default:
		return nil, fmt.Errorf("unrecognized sdbf magic %q", magic)
	}

	sd.bfSize = uint32(bfSize)
	sd.maxElem = uint32(maxElem)
	sd.bfCount = uint32(bfCount)
	sd.computeHamming()

	return sd, nil
}

// createSdbf creates and digests a sdbf from a byte buffer. Configuration is
// snapshotted from the package-level defaults at this point; subsequent changes
// to the defaults do not affect this digest.
//
// IMPORTANT: Do not add a default index bloom filter here. Adding one causes
// hash mismatches with the reference implementation.
func createSdbf(buffer []uint8, ddBlockSize uint32) (*sdbf, error) {
	sd := &sdbf{
		bfSize:         BfSize,
		bfCount:        1,
		bigFilters:     []*bloomFilter{mustNewBloomFilter(bigFilter, defaultHashCount, bigFilterElem)},
		popWinSize:     PopWinSize,
		threshold:      Threshold,
		blockSize:      BlockSize,
		entropyWinSize: EntropyWinSize,
	}

	fileSize := uint64(len(buffer))
	sd.origFileSize = fileSize
	if ddBlockSize == 0 { // stream mode
		sd.maxElem = MaxElem
		sd.generateChunkSdbf(buffer, 32*mB)
	} else { // block mode
		sd.maxElem = MaxElemDd
		ddBlockCnt := fileSize / uint64(ddBlockSize)
		if fileSize%uint64(ddBlockSize) >= MinFileSize {
			ddBlockCnt++
		}
		sd.bfCount = uint32(ddBlockCnt)
		sd.ddBlockSize = ddBlockSize
		sd.buffer = make([]uint8, ddBlockCnt*uint64(BfSize))
		sd.elemCounts = make([]uint16, ddBlockCnt)
		sd.generateBlockSdbf(buffer)
	}
	sd.computeHamming()

	return sd, nil
}

func (sd *sdbf) Size() uint64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return uint64(sd.bfSize) * uint64(sd.bfCount)
}

func (sd *sdbf) InputSize() uint64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.origFileSize
}

func (sd *sdbf) FilterCount() uint32 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	return sd.bfCount
}

func (sd *sdbf) FeatureDensity() float64 {
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	if sd.origFileSize == 0 {
		return 0
	}
	var totalElements uint64
	if sd.elemCounts == nil {
		// Stream mode: all filters except the last hold maxElem elements.
		if sd.bfCount > 0 {
			totalElements = uint64(sd.bfCount-1)*uint64(sd.maxElem) + uint64(sd.lastCount)
		}
	} else {
		// DD (block) mode: each filter tracks its own count.
		for i := uint32(0); i < sd.bfCount; i++ {
			totalElements += uint64(sd.elemCounts[i])
		}
	}
	return float64(totalElements) / float64(sd.origFileSize)
}

func (sd *sdbf) Compare(other Sdbf) int {
	return sd.CompareSample(other, 0)
}

func (sd *sdbf) CompareSample(other Sdbf, sample uint32) int {
	o := other.(*sdbf)
	sd.mu.RLock()
	defer sd.mu.RUnlock()
	o.mu.RLock()
	defer o.mu.RUnlock()
	return sdbfScore(sd, o, sample)
}

func (sd *sdbf) String() string {
	sd.mu.RLock()
	defer sd.mu.RUnlock()

	var sb strings.Builder
	isStream := sd.elemCounts == nil
	if isStream {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicStream, sdbfVersion))
	} else {
		sb.WriteString(fmt.Sprintf("%s:%02d:", magicDD, sdbfVersion))
	}
	sb.WriteString(fmt.Sprintf("1:-:%d:sha1:", sd.origFileSize))
	sb.WriteString(fmt.Sprintf("%d:%d:%x:", sd.bfSize, defaultHashCount, defaultMask))

	if isStream {
		sb.WriteString(fmt.Sprintf("%d:%d:%d:", sd.maxElem, sd.bfCount, sd.lastCount))
		qt, rem := sd.bfCount/6, sd.bfCount%6
		b64Block := uint64(6 * sd.bfSize)
		var pos uint64
		for i := uint32(0); i < qt; i++ {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+b64Block]))
			pos += b64Block
		}
		if rem > 0 {
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[pos : pos+uint64(rem*sd.bfSize)]))
		}
	} else {
		sb.WriteString(fmt.Sprintf("%d:%d:%d", sd.maxElem, sd.bfCount, sd.ddBlockSize))
		for i := uint32(0); i < sd.bfCount; i++ {
			sb.WriteString(fmt.Sprintf(":%02x:", sd.elemCounts[i]))
			sb.WriteString(base64.StdEncoding.EncodeToString(sd.buffer[i*sd.bfSize : i*sd.bfSize+sd.bfSize]))
		}
	}
	sb.WriteByte('\n')

	return sb.String()
}

// elemCount returns the element count for the filter at index.
// The caller must hold at least a read lock.
func (sd *sdbf) elemCount(index uint32) uint32 {
	if sd.elemCounts == nil {
		if index < sd.bfCount-1 {
			return sd.maxElem
		}
		return sd.lastCount
	}
	return uint32(sd.elemCounts[index])
}

// computeHamming precomputes the hamming weight for each bloom filter in the buffer.
func (sd *sdbf) computeHamming() {
	sd.hamming = make([]uint16, sd.bfCount)
	for i := uint32(0); i < sd.bfCount; i++ {
		var h uint16
		for _, b := range sd.buffer[sd.bfSize*i : sd.bfSize*(i+1)] {
			h += uint16(bits.OnesCount8(b))
		}
		sd.hamming[i] = h
	}
}

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
