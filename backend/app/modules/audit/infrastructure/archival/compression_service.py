"""Compression service for audit data archival.

This module provides efficient compression and decompression of audit data
for archival storage with support for various compression algorithms.
"""

import asyncio
import bz2
import gzip
import json
import lzma
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO
from typing import Any

from app.core.errors import InfrastructureError
from app.core.logging import get_logger
from app.modules.audit.domain.entities.audit_entry import AuditEntry

logger = get_logger(__name__)


class CompressionService:
    """
    Service for compressing and decompressing audit data.

    Provides multiple compression algorithms with automatic selection
    based on data characteristics and requirements.
    """

    # Compression algorithms with their characteristics
    ALGORITHMS = {
        "gzip": {
            "module": gzip,
            "speed": "medium",
            "ratio": "good",
            "cpu": "medium",
            "extension": ".gz",
        },
        "zlib": {
            "module": zlib,
            "speed": "fast",
            "ratio": "moderate",
            "cpu": "low",
            "extension": ".z",
        },
        "bz2": {
            "module": bz2,
            "speed": "slow",
            "ratio": "excellent",
            "cpu": "high",
            "extension": ".bz2",
        },
        "lzma": {
            "module": lzma,
            "speed": "very_slow",
            "ratio": "best",
            "cpu": "very_high",
            "extension": ".xz",
        },
    }

    def __init__(
        self,
        default_algorithm: str = "gzip",
        compression_level: int = 6,
        chunk_size: int = 1024 * 1024,  # 1MB chunks
        max_workers: int = 4,
    ):
        """
        Initialize compression service.

        Args:
            default_algorithm: Default compression algorithm
            compression_level: Compression level (1-9)
            chunk_size: Size of chunks for streaming compression
            max_workers: Maximum worker threads for parallel compression
        """
        if default_algorithm not in self.ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {default_algorithm}")

        self.default_algorithm = default_algorithm
        self.compression_level = max(1, min(9, compression_level))
        self.chunk_size = chunk_size
        self.executor = ThreadPoolExecutor(max_workers=max_workers)

    async def compress_entries(
        self,
        entries: list[AuditEntry],
        algorithm: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> bytes:
        """
        Compress a list of audit entries.

        Args:
            entries: List of audit entries to compress
            algorithm: Compression algorithm to use
            metadata: Additional metadata to include

        Returns:
            Compressed data
        """
        if not entries:
            raise ValueError("No entries to compress")

        algorithm = algorithm or self.default_algorithm

        try:
            # Prepare data structure
            data = {
                "version": "1.0",
                "algorithm": algorithm,
                "compressed_at": datetime.utcnow().isoformat(),
                "entry_count": len(entries),
                "metadata": metadata or {},
                "entries": [entry.to_dict() for entry in entries],
            }

            # Convert to JSON
            json_data = json.dumps(data, separators=(",", ":"), default=str)
            json_bytes = json_data.encode("utf-8")

            # Record original size
            original_size = len(json_bytes)

            # Compress in thread pool to avoid blocking
            compressed_data = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._compress_data, json_bytes, algorithm
            )

            compressed_size = len(compressed_data)
            compression_ratio = (1 - compressed_size / original_size) * 100

            logger.info(
                "Compressed audit entries",
                count=len(entries),
                algorithm=algorithm,
                original_size=original_size,
                compressed_size=compressed_size,
                compression_ratio=f"{compression_ratio:.1f}%",
            )

            return compressed_data

        except Exception as e:
            logger.exception("Compression failed", algorithm=algorithm, error=str(e))
            raise InfrastructureError(f"Compression failed: {e!s}")

    async def decompress_entries(
        self, compressed_data: bytes, algorithm: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Decompress audit entries.

        Args:
            compressed_data: Compressed data
            algorithm: Compression algorithm (auto-detect if not specified)

        Returns:
            List of entry dictionaries
        """
        if not compressed_data:
            raise ValueError("No data to decompress")

        try:
            # Auto-detect algorithm if not specified
            if not algorithm:
                algorithm = self._detect_algorithm(compressed_data)

            # Decompress in thread pool
            json_bytes = await asyncio.get_event_loop().run_in_executor(
                self.executor, self._decompress_data, compressed_data, algorithm
            )

            # Parse JSON
            data = json.loads(json_bytes.decode("utf-8"))

            # Validate structure
            if "entries" not in data:
                raise ValueError("Invalid archive format: missing entries")

            logger.info(
                "Decompressed audit entries",
                count=len(data["entries"]),
                algorithm=algorithm,
                compressed_size=len(compressed_data),
                decompressed_size=len(json_bytes),
            )

            return data["entries"]

        except Exception as e:
            logger.exception("Decompression failed", algorithm=algorithm, error=str(e))
            raise InfrastructureError(f"Decompression failed: {e!s}")

    async def compress_stream(
        self, data_generator, output_stream, algorithm: str | None = None
    ) -> dict[str, Any]:
        """
        Compress data from a generator/stream.

        Args:
            data_generator: Async generator yielding data chunks
            output_stream: Output stream to write compressed data
            algorithm: Compression algorithm

        Returns:
            Compression statistics
        """
        algorithm = algorithm or self.default_algorithm
        stats = {
            "algorithm": algorithm,
            "chunks_processed": 0,
            "original_size": 0,
            "compressed_size": 0,
            "start_time": datetime.utcnow(),
        }

        try:
            # Get compressor
            compressor = self._get_compressor(algorithm)

            # Process chunks
            async for chunk in data_generator:
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")

                stats["original_size"] += len(chunk)

                # Compress chunk
                compressed_chunk = await asyncio.get_event_loop().run_in_executor(
                    self.executor, compressor.compress, chunk
                )

                if compressed_chunk:
                    await output_stream.write(compressed_chunk)
                    stats["compressed_size"] += len(compressed_chunk)

                stats["chunks_processed"] += 1

            # Flush compressor
            final_data = await asyncio.get_event_loop().run_in_executor(
                self.executor, compressor.flush
            )

            if final_data:
                await output_stream.write(final_data)
                stats["compressed_size"] += len(final_data)

            stats["end_time"] = datetime.utcnow()
            stats["duration_seconds"] = (
                stats["end_time"] - stats["start_time"]
            ).total_seconds()
            stats["compression_ratio"] = (
                (1 - stats["compressed_size"] / stats["original_size"]) * 100
                if stats["original_size"] > 0
                else 0
            )

            logger.info("Stream compression completed", stats=stats)

            return stats

        except Exception as e:
            logger.exception(
                "Stream compression failed", algorithm=algorithm, error=str(e)
            )
            raise InfrastructureError(f"Stream compression failed: {e!s}")

    def _compress_data(self, data: bytes, algorithm: str) -> bytes:
        """Compress data using specified algorithm."""
        algo_info = self.ALGORITHMS[algorithm]
        algo_info["module"]

        if algorithm == "gzip":
            return gzip.compress(data, compresslevel=self.compression_level)
        if algorithm == "zlib":
            return zlib.compress(data, level=self.compression_level)
        if algorithm == "bz2":
            return bz2.compress(data, compresslevel=self.compression_level)
        if algorithm == "lzma":
            return lzma.compress(
                data, format=lzma.FORMAT_XZ, preset=self.compression_level
            )
        raise ValueError(f"Unknown algorithm: {algorithm}")

    def _decompress_data(self, data: bytes, algorithm: str) -> bytes:
        """Decompress data using specified algorithm."""
        algo_info = self.ALGORITHMS[algorithm]
        algo_info["module"]

        if algorithm == "gzip":
            return gzip.decompress(data)
        if algorithm == "zlib":
            return zlib.decompress(data)
        if algorithm == "bz2":
            return bz2.decompress(data)
        if algorithm == "lzma":
            return lzma.decompress(data)
        raise ValueError(f"Unknown algorithm: {algorithm}")

    def _get_compressor(self, algorithm: str):
        """Get a compressor object for streaming compression."""
        if algorithm == "gzip":
            return gzip.GzipFile(
                mode="wb", fileobj=BytesIO(), compresslevel=self.compression_level
            )
        if algorithm == "zlib":
            return zlib.compressobj(level=self.compression_level)
        if algorithm == "bz2":
            return bz2.BZ2Compressor(compresslevel=self.compression_level)
        if algorithm == "lzma":
            return lzma.LZMACompressor(
                format=lzma.FORMAT_XZ, preset=self.compression_level
            )
        raise ValueError(f"Unknown algorithm: {algorithm}")

    def _detect_algorithm(self, data: bytes) -> str:
        """Auto-detect compression algorithm from data."""
        # Check magic bytes
        if data.startswith(b"\x1f\x8b"):  # gzip
            return "gzip"
        if data.startswith((b"x\x9c", b"x\x01")):  # zlib
            return "zlib"
        if data.startswith(b"BZh"):  # bz2
            return "bz2"
        if data.startswith(b"\xfd7zXZ\x00"):  # xz/lzma
            return "lzma"
        # Try each algorithm
        for algo in ["gzip", "zlib", "bz2", "lzma"]:
            try:
                self._decompress_data(data[:1024], algo)
                return algo
            except:
                continue

        raise ValueError("Unable to detect compression algorithm")

    def select_algorithm(self, data_size: int, priority: str = "balanced") -> str:
        """
        Select optimal compression algorithm based on requirements.

        Args:
            data_size: Size of data to compress
            priority: 'speed', 'ratio', or 'balanced'

        Returns:
            Recommended algorithm
        """
        if priority == "speed":
            # For speed, prefer zlib for small data, gzip for larger
            return "zlib" if data_size < 1024 * 1024 else "gzip"
        if priority == "ratio":
            # For best compression, use lzma for small data, bz2 for larger
            return "lzma" if data_size < 10 * 1024 * 1024 else "bz2"
        # Balanced approach based on data size
        if data_size < 1024 * 1024:  # < 1MB
            return "zlib"
        if data_size < 100 * 1024 * 1024:  # < 100MB
            return "gzip"
        return "bz2"

    async def benchmark_algorithms(
        self, sample_data: bytes
    ) -> dict[str, dict[str, Any]]:
        """
        Benchmark compression algorithms on sample data.

        Args:
            sample_data: Sample data to benchmark

        Returns:
            Benchmark results for each algorithm
        """
        results = {}

        for algo_name in self.ALGORITHMS:
            start_time = datetime.utcnow()

            try:
                # Compress
                compressed = await asyncio.get_event_loop().run_in_executor(
                    self.executor, self._compress_data, sample_data, algo_name
                )

                compress_time = (datetime.utcnow() - start_time).total_seconds()

                # Decompress
                decompress_start = datetime.utcnow()
                await asyncio.get_event_loop().run_in_executor(
                    self.executor, self._decompress_data, compressed, algo_name
                )

                decompress_time = (datetime.utcnow() - decompress_start).total_seconds()

                results[algo_name] = {
                    "compress_time": compress_time,
                    "decompress_time": decompress_time,
                    "total_time": compress_time + decompress_time,
                    "compressed_size": len(compressed),
                    "compression_ratio": (1 - len(compressed) / len(sample_data)) * 100,
                    "success": True,
                }

            except Exception as e:
                results[algo_name] = {"success": False, "error": str(e)}

        return results

    def shutdown(self) -> None:
        """Shutdown the compression service."""
        self.executor.shutdown(wait=True)


__all__ = ["CompressionService"]
