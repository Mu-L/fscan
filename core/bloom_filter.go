package core

import (
	"hash/fnv"
)

// BloomFilter 布隆过滤器，用于ICMP包去重
type BloomFilter struct {
	bits []bool
	size uint32
	k    uint32 // hash函数数量
}

// NewBloomFilter 创建布隆过滤器
// size: 预期元素数量
// falsePositiveRate: 期望的误判率（通常0.01即1%）
func NewBloomFilter(size int, falsePositiveRate float64) *BloomFilter {
	// 计算最优bit数组大小: m = -n*ln(p) / (ln(2)^2)
	// 简化计算：m ≈ n * 10 for p=0.01
	m := uint32(size * 10)
	if m < 1024 {
		m = 1024 // 最小1KB
	}

	// 计算最优hash函数数量: k = (m/n) * ln(2)
	// 简化：k ≈ 7 for p=0.01
	k := uint32(7)

	return &BloomFilter{
		bits: make([]bool, m),
		size: m,
		k:    k,
	}
}

// Add 添加元素到过滤器
func (bf *BloomFilter) Add(data string) {
	for i := uint32(0); i < bf.k; i++ {
		pos := bf.hash(data, i)
		bf.bits[pos] = true
	}
}

// Contains 检查元素是否可能存在
// 返回true：可能存在（有误判可能）
// 返回false：一定不存在
func (bf *BloomFilter) Contains(data string) bool {
	for i := uint32(0); i < bf.k; i++ {
		pos := bf.hash(data, i)
		if !bf.bits[pos] {
			return false
		}
	}
	return true
}

// hash 计算hash值
func (bf *BloomFilter) hash(data string, seed uint32) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(data))
	// 添加seed实现多个hash函数
	for i := uint32(0); i < seed; i++ {
		_, _ = h.Write([]byte{byte(i)})
	}
	return h.Sum32() % bf.size
}
