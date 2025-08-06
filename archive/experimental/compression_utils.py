# compression_utils.py - Intelligent Compression System
import time
import zlib
import gzip
import bz2
import lzma
import logging
from typing import Dict, Optional, Tuple, Union, List
from dataclasses import dataclass
from enum import Enum

# Optional high-performance compression libraries
try:
    import lz4.frame as lz4

    LZ4_AVAILABLE = True
except ImportError:
    LZ4_AVAILABLE = False

try:
    import zstandard as zstd

    ZSTD_AVAILABLE = True
except ImportError:
    ZSTD_AVAILABLE = False

try:
    import brotli

    BROTLI_AVAILABLE = True
except ImportError:
    BROTLI_AVAILABLE = False

logger = logging.getLogger(__name__)


class CompressionAlgorithm(Enum):
    """Supported compression algorithms"""
    NONE = "none"
    LZ4 = "lz4"
    ZSTD = "zstd"
    GZIP = "gzip"
    BROTLI = "brotli"
    ZLIB = "zlib"
    BZ2 = "bz2"
    LZMA = "lzma"


@dataclass
class CompressionResult:
    """Result of compression operation"""
    compressed_data: bytes
    original_size: int
    compressed_size: int
    compression_ratio: float
    compression_time_ms: float
    algorithm: str

    @property
    def space_saved_percent(self) -> float:
        """Calculate space saved percentage"""
        if self.original_size == 0:
            return 0.0
        return (1 - (self.compressed_size / self.original_size)) * 100


class CompressionEngine:
    """High-performance compression engine with multiple algorithms"""

    def __init__(self, config: Dict):
        self.enabled = config.get("enabled", False)
        self.algorithm = CompressionAlgorithm(config.get("algorithm", "lz4"))
        self.compression_level = config.get("compression_level", 6)
        self.min_size_threshold = config.get("min_size_threshold", 100)
        self.max_size_threshold = config.get("max_size_threshold", 10 * 1024 * 1024)  # 10MB
        self.adaptive_algorithm = config.get("adaptive_algorithm", False)
        self.benchmark_mode = config.get("benchmark_mode", False)

        # Performance tracking
        self.metrics = {
            "compressions": 0,
            "decompressions": 0,
            "total_input_bytes": 0,
            "total_output_bytes": 0,
            "total_compression_time_ms": 0,
            "total_decompression_time_ms": 0,
            "skipped_small_files": 0,
            "skipped_large_files": 0,
            "errors": 0
        }

        # Algorithm-specific configurations
        self._init_compressors()

    def _init_compressors(self):
        """Initialize algorithm-specific compressors"""
        self.compressors = {}

        # LZ4 compressor (fastest)
        if LZ4_AVAILABLE:
            self.compressors[CompressionAlgorithm.LZ4] = {
                "compress": lambda data: lz4.compress(data, compression_level=self.compression_level),
                "decompress": lz4.decompress,
                "available": True
            }
        else:
            self.compressors[CompressionAlgorithm.LZ4] = {"available": False}

        # Zstandard compressor (balanced)
        if ZSTD_AVAILABLE:
            cctx = zstd.ZstdCompressor(level=self.compression_level)
            dctx = zstd.ZstdDecompressor()
            self.compressors[CompressionAlgorithm.ZSTD] = {
                "compress": cctx.compress,
                "decompress": dctx.decompress,
                "available": True
            }
        else:
            self.compressors[CompressionAlgorithm.ZSTD] = {"available": False}

        # Brotli compressor (best ratio)
        if BROTLI_AVAILABLE:
            self.compressors[CompressionAlgorithm.BROTLI] = {
                "compress": lambda data: brotli.compress(data, quality=self.compression_level),
                "decompress": brotli.decompress,
                "available": True
            }
        else:
            self.compressors[CompressionAlgorithm.BROTLI] = {"available": False}

        # Built-in compressors (always available)
        self.compressors[CompressionAlgorithm.GZIP] = {
            "compress": lambda data: gzip.compress(data, compresslevel=self.compression_level),
            "decompress": gzip.decompress,
            "available": True
        }

        self.compressors[CompressionAlgorithm.ZLIB] = {
            "compress": lambda data: zlib.compress(data, level=self.compression_level),
            "decompress": zlib.decompress,
            "available": True
        }

        self.compressors[CompressionAlgorithm.BZ2] = {
            "compress": lambda data: bz2.compress(data, compresslevel=self.compression_level),
            "decompress": bz2.decompress,
            "available": True
        }

        self.compressors[CompressionAlgorithm.LZMA] = {
            "compress": lambda data: lzma.compress(data, preset=self.compression_level),
            "decompress": lzma.decompress,
            "available": True
        }

    def _should_compress(self, data: bytes) -> bool:
        """Determine if data should be compressed"""
        if not self.enabled:
            return False

        size = len(data)

        # Skip very small files
        if size < self.min_size_threshold:
            self.metrics["skipped_small_files"] += 1
            return False

        # Skip very large files
        if size > self.max_size_threshold:
            self.metrics["skipped_large_files"] += 1
            return False

        return True

    def _select_algorithm(self, data: bytes) -> CompressionAlgorithm:
        """Select optimal compression algorithm"""
        if not self.adaptive_algorithm:
            return self.algorithm

        # Adaptive algorithm selection based on data characteristics
        data_size = len(data)

        # For small data, use fastest algorithm
        if data_size < 1024:  # 1KB
            return CompressionAlgorithm.LZ4 if LZ4_AVAILABLE else CompressionAlgorithm.ZLIB

        # For medium data, use balanced algorithm
        elif data_size < 64 * 1024:  # 64KB
            return CompressionAlgorithm.ZSTD if ZSTD_AVAILABLE else CompressionAlgorithm.GZIP

        # For large data, use best compression
        else:
            return CompressionAlgorithm.BROTLI if BROTLI_AVAILABLE else CompressionAlgorithm.LZMA

    def _benchmark_algorithms(self, data: bytes) -> Dict:
        """Benchmark all available algorithms"""
        results = {}

        for algo in CompressionAlgorithm:
            if algo == CompressionAlgorithm.NONE:
                continue

            compressor = self.compressors.get(algo)
            if not compressor or not compressor.get("available"):
                continue

            try:
                start_time = time.perf_counter()
                compressed = compressor["compress"](data)
                compression_time = (time.perf_counter() - start_time) * 1000

                results[algo.value] = {
                    "compressed_size": len(compressed),
                    "compression_ratio": len(data) / len(compressed),
                    "compression_time_ms": compression_time,
                    "space_saved_percent": (1 - (len(compressed) / len(data))) * 100
                }

            except Exception as e:
                logger.warning(f"Benchmark failed for {algo.value}: {e}")
                results[algo.value] = {"error": str(e)}

        return results

    def compress(self, data: bytes, metadata: Optional[Dict] = None) -> Union[bytes, CompressionResult]:
        """Compress data with selected algorithm"""
        if not self._should_compress(data):
            if self.benchmark_mode:
                return CompressionResult(
                    compressed_data=data,
                    original_size=len(data),
                    compressed_size=len(data),
                    compression_ratio=1.0,
                    compression_time_ms=0.0,
                    algorithm="none"
                )
            return data

        try:
            # Select algorithm
            algorithm = self._select_algorithm(data)
            compressor = self.compressors.get(algorithm)

            if not compressor or not compressor.get("available"):
                logger.warning(f"Algorithm {algorithm.value} not available, falling back to zlib")
                algorithm = CompressionAlgorithm.ZLIB
                compressor = self.compressors[algorithm]

            # Perform compression
            start_time = time.perf_counter()
            compressed_data = compressor["compress"](data)
            compression_time = (time.perf_counter() - start_time) * 1000

            # Update metrics
            self.metrics["compressions"] += 1
            self.metrics["total_input_bytes"] += len(data)
            self.metrics["total_output_bytes"] += len(compressed_data)
            self.metrics["total_compression_time_ms"] += compression_time

            # Check if compression was beneficial
            if len(compressed_data) >= len(data):
                logger.debug(f"Compression not beneficial: {len(data)} -> {len(compressed_data)} bytes")
                if self.benchmark_mode:
                    return CompressionResult(
                        compressed_data=data,
                        original_size=len(data),
                        compressed_size=len(data),
                        compression_ratio=1.0,
                        compression_time_ms=compression_time,
                        algorithm="none"
                    )
                return data

            # Add algorithm header (1 byte)
            result_data = bytes([algorithm.value.encode()[0]]) + compressed_data

            if self.benchmark_mode:
                return CompressionResult(
                    compressed_data=result_data,
                    original_size=len(data),
                    compressed_size=len(result_data),
                    compression_ratio=len(data) / len(result_data),
                    compression_time_ms=compression_time,
                    algorithm=algorithm.value
                )

            return result_data

        except Exception as e:
            logger.error(f"Compression failed: {e}")
            self.metrics["errors"] += 1
            return data  # Return original data on error

    def decompress(self, data: bytes, metadata: Optional[Dict] = None) -> bytes:
        """Decompress data"""
        if not self.enabled or len(data) == 0:
            return data

        try:
            # Check if data has compression header
            if len(data) < 2:
                return data  # Too small to be compressed

            # Extract algorithm from header
            algo_byte = data[0]
            compressed_data = data[1:]

            # Map byte to algorithm
            algorithm = None
            for algo in CompressionAlgorithm:
                if algo.value.encode()[0] == algo_byte:
                    algorithm = algo
                    break

            if algorithm is None or algorithm == CompressionAlgorithm.NONE:
                return data  # Not compressed or unknown algorithm

            # Get decompressor
            compressor = self.compressors.get(algorithm)
            if not compressor or not compressor.get("available"):
                logger.error(f"Decompressor for {algorithm.value} not available")
                return data

            # Perform decompression
            start_time = time.perf_counter()
            decompressed_data = compressor["decompress"](compressed_data)
            decompression_time = (time.perf_counter() - start_time) * 1000

            # Update metrics
            self.metrics["decompressions"] += 1
            self.metrics["total_decompression_time_ms"] += decompression_time

            return decompressed_data

        except Exception as e:
            logger.error(f"Decompression failed: {e}")
            self.metrics["errors"] += 1
            return data  # Return original data on error

    def get_metrics(self) -> Dict:
        """Get compression metrics"""
        metrics = self.metrics.copy()

        # Calculate derived metrics
        if metrics["compressions"] > 0:
            metrics["avg_compression_ratio"] = (
                metrics["total_input_bytes"] / metrics["total_output_bytes"]
                if metrics["total_output_bytes"] > 0 else 1.0
            )
            metrics["avg_compression_time_ms"] = (
                    metrics["total_compression_time_ms"] / metrics["compressions"]
            )

        if metrics["decompressions"] > 0:
            metrics["avg_decompression_time_ms"] = (
                    metrics["total_decompression_time_ms"] / metrics["decompressions"]
            )

        return metrics

    def benchmark(self, test_data: bytes) -> Dict:
        """Benchmark all available algorithms"""
        if not self.enabled:
            return {"error": "Compression disabled"}

        logger.info(f"Benchmarking compression algorithms with {len(test_data)} bytes")
        return self._benchmark_algorithms(test_data)

    def get_available_algorithms(self) -> List[str]:
        """Get list of available compression algorithms"""
        available = []
        for algo, compressor in self.compressors.items():
            if compressor.get("available", False):
                available.append(algo.value)
        return available

    def is_healthy(self) -> bool:
        """Check if compression system is healthy"""
        try:
            # Test compression/decompression
            test_data = b"health_check_test_data_for_compression" * 10
            compressed = self.compress(test_data)
            decompressed = self.decompress(compressed)

            # Handle CompressionResult object
            if isinstance(compressed, CompressionResult):
                compressed = compressed.compressed_data

            return decompressed == test_data

        except Exception as e:
            logger.error(f"Compression health check failed: {e}")
            return False


# Utility functions for easy integration
def create_compression_engine(config: Dict) -> CompressionEngine:
    """Factory function to create compression engine"""
    return CompressionEngine(config)


def compress_data(data: bytes, algorithm: str = "lz4", level: int = 6) -> bytes:
    """Quick compression utility"""
    config = {
        "enabled": True,
        "algorithm": algorithm,
        "compression_level": level
    }
    engine = CompressionEngine(config)
    result = engine.compress(data)
    return result.compressed_data if isinstance(result, CompressionResult) else result


def decompress_data(data: bytes) -> bytes:
    """Quick decompression utility"""
    config = {"enabled": True}
    engine = CompressionEngine(config)
    return engine.decompress(data)