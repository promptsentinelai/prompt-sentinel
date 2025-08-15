# Performance Benchmark Summary

Generated: 2025-08-15 13:17:14

## Key Metrics

### Heuristic Detection
| Test Case | Avg (ms) | Median (ms) | Text Length |
|-----------|----------|-------------|-------------|
| Normal text | 0.02 | 0.02 | 33 |
| Short injection | 0.02 | 0.02 | 23 |
| Long injection | 0.07 | 0.07 | 370 |
| Complex prompt | 0.11 | 0.11 | 620 |
| Very long text | 1.50 | 1.50 | 10500 |

### PII Detection
| Test Case | Avg (ms) | PII Found | Text Length |
|-----------|----------|-----------|-------------|
| No PII | 0.02 | 0 | 58 |
| Email only | 0.02 | 1 | 49 |
| Phone only | 0.02 | 1 | 33 |
| Multiple PII | 0.03 | 2 | 58 |
| Large text with PII | 0.49 | 1 | 2216 |

### Scaling Performance
| Size (chars) | Time (ms) | Time/KB (ms) |
|--------------|-----------|-------------|
| 100 | 0.03 | 0.29 |
| 500 | 0.08 | 0.17 |
| 1000 | 0.16 | 0.16 |
| 5000 | 0.74 | 0.15 |
| 10000 | 1.47 | 0.15 |
| 50000 | 3.84 | 0.08 |

## Performance Assessment

✅ Heuristic detection < 5ms for normal text
✅ PII detection < 20ms

## Recommendations

1. **Cache compiled regex patterns** - Current compilation adds overhead
2. **Implement detection result caching** - For repeated prompts
3. **Parallelize independent detections** - Heuristic and PII can run concurrently
4. **Optimize pattern matching** - Pre-filter with simpler patterns first
