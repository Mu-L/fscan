package core

import (
	"fmt"
	"testing"
)

/*
bloom_filter_test.go - BloomFilter 高价值测试

测试重点：
1. 基本正确性 - Add后Contains返回true，未添加的返回false
2. 误判率验证 - 实际误判率应接近理论值(1%)
3. 大规模数据 - 模拟真实ICMP去重场景

不测试：
- 内部哈希实现细节
- 精确的数学公式验证
*/

// TestBloomFilter_BasicCorrectness 基本正确性测试
func TestBloomFilter_BasicCorrectness(t *testing.T) {
	bf := NewBloomFilter(1000, 0.01)

	// 添加元素后应该能找到
	testData := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	for _, data := range testData {
		bf.Add(data)
	}

	for _, data := range testData {
		if !bf.Contains(data) {
			t.Errorf("已添加的元素 %s 应该返回 true", data)
		}
	}

	// 未添加的元素（大概率）返回false
	notAdded := []string{
		"8.8.8.8",
		"1.1.1.1",
		"255.255.255.255",
	}

	falsePositives := 0
	for _, data := range notAdded {
		if bf.Contains(data) {
			falsePositives++
		}
	}

	// 3个未添加元素全部误判的概率极低（<0.0001%）
	if falsePositives == len(notAdded) {
		t.Error("所有未添加元素都返回true，布隆过滤器可能有问题")
	}
}

// TestBloomFilter_FalsePositiveRate 误判率验证
//
// 对于 n=10000, p=0.01 的布隆过滤器：
// 实际误判率应该在 0.5% - 2% 之间（允许统计波动）
func TestBloomFilter_FalsePositiveRate(t *testing.T) {
	n := 10000 // 添加的元素数
	bf := NewBloomFilter(n, 0.01)

	// 添加n个元素
	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("added_%d", i))
	}

	// 测试n个未添加的元素
	falsePositives := 0
	testCount := n
	for i := 0; i < testCount; i++ {
		if bf.Contains(fmt.Sprintf("not_added_%d", i)) {
			falsePositives++
		}
	}

	actualRate := float64(falsePositives) / float64(testCount)

	// 允许的误判率范围：0.1% - 3%（考虑统计波动）
	if actualRate > 0.03 {
		t.Errorf("误判率过高: %.2f%% (期望 < 3%%)", actualRate*100)
	}

	t.Logf("实际误判率: %.2f%% (%d/%d)", actualRate*100, falsePositives, testCount)
}

// TestBloomFilter_LargeScale 大规模数据测试
//
// 模拟真实的ICMP去重场景：100万个IP地址
func TestBloomFilter_LargeScale(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过大规模测试")
	}

	n := 1000000 // 100万
	bf := NewBloomFilter(n, 0.01)

	// 添加100万个元素
	for i := 0; i < n; i++ {
		bf.Add(fmt.Sprintf("192.168.%d.%d", i/256, i%256))
	}

	// 验证已添加的元素
	sampleSize := 1000
	for i := 0; i < sampleSize; i++ {
		idx := i * (n / sampleSize)
		data := fmt.Sprintf("192.168.%d.%d", idx/256, idx%256)
		if !bf.Contains(data) {
			t.Errorf("已添加的元素 %s 返回 false", data)
		}
	}

	// 测试未添加元素的误判率
	falsePositives := 0
	for i := 0; i < sampleSize; i++ {
		if bf.Contains(fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256)) {
			falsePositives++
		}
	}

	actualRate := float64(falsePositives) / float64(sampleSize)
	if actualRate > 0.03 {
		t.Errorf("大规模场景误判率过高: %.2f%%", actualRate*100)
	}

	t.Logf("100万元素场景误判率: %.2f%%", actualRate*100)
}

// TestBloomFilter_NoFalseNegative 验证无假阴性
//
// 布隆过滤器的核心保证：已添加的元素必定返回true
func TestBloomFilter_NoFalseNegative(t *testing.T) {
	bf := NewBloomFilter(10000, 0.01)

	// 添加5000个元素
	added := make([]string, 5000)
	for i := range added {
		added[i] = fmt.Sprintf("element_%d", i)
		bf.Add(added[i])
	}

	// 全部验证
	for _, data := range added {
		if !bf.Contains(data) {
			t.Fatalf("假阴性！已添加的元素 %s 返回 false", data)
		}
	}
}

// TestBloomFilter_EmptyFilter 空过滤器测试
func TestBloomFilter_EmptyFilter(t *testing.T) {
	bf := NewBloomFilter(100, 0.01)

	// 空过滤器应该对任何查询返回false
	testCases := []string{"anything", "192.168.1.1", ""}
	for _, tc := range testCases {
		if bf.Contains(tc) {
			t.Errorf("空过滤器对 %q 返回 true", tc)
		}
	}
}
