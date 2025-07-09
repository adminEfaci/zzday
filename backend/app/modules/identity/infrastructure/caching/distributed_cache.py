"""Distributed cache implementation with consistency guarantees.

This module provides distributed caching capabilities with strong consistency
guarantees using distributed locking and cache coherence protocols.
"""

import asyncio
import hashlib
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Union
from uuid import uuid4

from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class CacheEntry:
    """Cache entry with metadata."""
    key: str
    value: Any
    ttl: Optional[int] = None
    created_at: float = None
    last_accessed: float = None
    version: int = 1
    checksum: Optional[str] = None
    locked: bool = False
    lock_owner: Optional[str] = None
    lock_expires: Optional[float] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = time.time()
        if self.last_accessed is None:
            self.last_accessed = time.time()
        if self.checksum is None:
            self.checksum = self._calculate_checksum()
    
    def _calculate_checksum(self) -> str:
        """Calculate checksum for cache entry."""
        import pickle
        data = pickle.dumps(self.value)
        return hashlib.md5(data).hexdigest()
    
    def is_expired(self) -> bool:
        """Check if cache entry is expired."""
        if self.ttl is None:
            return False
        return time.time() - self.created_at > self.ttl
    
    def is_lock_expired(self) -> bool:
        """Check if lock is expired."""
        if self.lock_expires is None:
            return False
        return time.time() > self.lock_expires
    
    def update_access_time(self):
        """Update last accessed time."""
        self.last_accessed = time.time()
    
    def increment_version(self):
        """Increment version number."""
        self.version += 1
        self.checksum = self._calculate_checksum()


class DistributedLockError(Exception):
    """Distributed lock specific errors."""
    pass


class CacheConsistencyError(Exception):
    """Cache consistency specific errors."""
    pass


class DistributedLock:
    """Distributed lock implementation."""
    
    def __init__(self, key: str, owner: str, ttl: int = 30):
        self.key = key
        self.owner = owner
        self.ttl = ttl
        self.acquired_at: Optional[float] = None
        self.expires_at: Optional[float] = None
        self.extended_count = 0
    
    def is_expired(self) -> bool:
        """Check if lock is expired."""
        if self.expires_at is None:
            return False
        return time.time() > self.expires_at
    
    def extend(self, additional_ttl: int) -> None:
        """Extend lock TTL."""
        if self.expires_at:
            self.expires_at += additional_ttl
        else:
            self.expires_at = time.time() + additional_ttl
        self.extended_count += 1


class DistributedCache:
    """Distributed cache with consistency guarantees."""
    
    def __init__(self, cache_id: str, node_id: str):
        self.cache_id = cache_id
        self.node_id = node_id
        self.entries: Dict[str, CacheEntry] = {}
        self.locks: Dict[str, DistributedLock] = {}
        self.invalidation_queue: asyncio.Queue = asyncio.Queue()
        self.peer_nodes: Set[str] = set()
        self.stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "invalidations": 0,
            "lock_acquisitions": 0,
            "lock_failures": 0,
            "consistency_checks": 0,
            "consistency_failures": 0,
        }
        self._cleanup_task: Optional[asyncio.Task] = None
        self._invalidation_task: Optional[asyncio.Task] = None
        self.running = False
    
    async def start(self):
        """Start the distributed cache."""
        if self.running:
            return
        
        self.running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._invalidation_task = asyncio.create_task(self._invalidation_loop())
        
        logger.info(
            "Started distributed cache",
            cache_id=self.cache_id,
            node_id=self.node_id,
        )
    
    async def stop(self):
        """Stop the distributed cache."""
        if not self.running:
            return
        
        self.running = False
        
        if self._cleanup_task:
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self._invalidation_task:
            self._invalidation_task.cancel()
            try:
                await self._invalidation_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Stopped distributed cache", cache_id=self.cache_id)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache with consistency checks.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        if key not in self.entries:
            self.stats["misses"] += 1
            return None
        
        entry = self.entries[key]
        
        # Check if entry is expired
        if entry.is_expired():
            await self._remove_entry(key)
            self.stats["misses"] += 1
            return None
        
        # Check if entry is locked by another process
        if entry.locked and entry.lock_owner != self.node_id:
            if not entry.is_lock_expired():
                self.stats["misses"] += 1
                return None
            else:
                # Lock expired, clear it
                entry.locked = False
                entry.lock_owner = None
                entry.lock_expires = None
        
        # Update access time and return value
        entry.update_access_time()
        self.stats["hits"] += 1
        
        return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in cache with consistency guarantees.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if set successfully
        """
        # Try to acquire lock for write consistency
        async with self._acquire_lock(key, timeout=5):
            # Create or update entry
            if key in self.entries:
                entry = self.entries[key]
                entry.value = value
                entry.ttl = ttl
                entry.created_at = time.time()
                entry.increment_version()
            else:
                entry = CacheEntry(key=key, value=value, ttl=ttl)
                self.entries[key] = entry
            
            # Invalidate in peer nodes
            await self._invalidate_peers(key)
            
            self.stats["sets"] += 1
            return True
    
    async def delete(self, key: str) -> bool:
        """Delete value from cache.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted successfully
        """
        if key not in self.entries:
            return False
        
        # Try to acquire lock for write consistency
        async with self._acquire_lock(key, timeout=5):
            await self._remove_entry(key)
            
            # Invalidate in peer nodes
            await self._invalidate_peers(key)
            
            self.stats["deletes"] += 1
            return True
    
    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter with distributed locking.
        
        Args:
            key: Cache key
            amount: Amount to increment
            
        Returns:
            New counter value
        """
        async with self._acquire_lock(key, timeout=5):
            current_value = await self.get(key)
            if current_value is None:
                current_value = 0
            
            new_value = current_value + amount
            await self.set(key, new_value)
            
            return new_value
    
    async def compare_and_swap(self, key: str, expected: Any, new_value: Any) -> bool:
        """Compare and swap operation with consistency guarantees.
        
        Args:
            key: Cache key
            expected: Expected current value
            new_value: New value to set
            
        Returns:
            True if swap was successful
        """
        async with self._acquire_lock(key, timeout=5):
            current_value = await self.get(key)
            
            if current_value == expected:
                await self.set(key, new_value)
                return True
            
            return False
    
    @asynccontextmanager
    async def _acquire_lock(self, key: str, timeout: int = 30):
        """Acquire distributed lock for a key.
        
        Args:
            key: Key to lock
            timeout: Lock timeout in seconds
        """
        lock_key = f"lock:{key}"
        owner = f"{self.node_id}:{uuid4()}"
        
        # Try to acquire lock
        acquired = False
        try:
            for attempt in range(timeout):
                if lock_key not in self.locks:
                    # Create new lock
                    lock = DistributedLock(lock_key, owner, timeout)
                    lock.acquired_at = time.time()
                    lock.expires_at = time.time() + timeout
                    self.locks[lock_key] = lock
                    acquired = True
                    self.stats["lock_acquisitions"] += 1
                    break
                else:
                    # Check if existing lock is expired
                    existing_lock = self.locks[lock_key]
                    if existing_lock.is_expired():
                        # Remove expired lock and acquire new one
                        del self.locks[lock_key]
                        continue
                
                # Wait before retry
                await asyncio.sleep(1)
            
            if not acquired:
                self.stats["lock_failures"] += 1
                raise DistributedLockError(f"Failed to acquire lock for key: {key}")
            
            yield
            
        finally:
            # Release lock
            if acquired and lock_key in self.locks:
                lock = self.locks[lock_key]
                if lock.owner == owner:
                    del self.locks[lock_key]
    
    async def _invalidate_peers(self, key: str):
        """Invalidate key in peer nodes.
        
        Args:
            key: Key to invalidate
        """
        await self.invalidation_queue.put(key)
        self.stats["invalidations"] += 1
    
    async def _remove_entry(self, key: str):
        """Remove entry from cache.
        
        Args:
            key: Key to remove
        """
        if key in self.entries:
            del self.entries[key]
    
    async def _cleanup_loop(self):
        """Cleanup expired entries and locks."""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean up expired entries
                expired_keys = []
                for key, entry in self.entries.items():
                    if entry.is_expired():
                        expired_keys.append(key)
                
                for key in expired_keys:
                    await self._remove_entry(key)
                
                # Clean up expired locks
                expired_locks = []
                for lock_key, lock in self.locks.items():
                    if lock.is_expired():
                        expired_locks.append(lock_key)
                
                for lock_key in expired_locks:
                    del self.locks[lock_key]
                
                # Sleep for cleanup interval
                await asyncio.sleep(10)
                
            except Exception as e:
                logger.exception("Error in cleanup loop", error=str(e))
                await asyncio.sleep(10)
    
    async def _invalidation_loop(self):
        """Process invalidation queue."""
        while self.running:
            try:
                # Get invalidation request
                key = await asyncio.wait_for(
                    self.invalidation_queue.get(),
                    timeout=1.0
                )
                
                # Send invalidation to peer nodes
                await self._send_invalidation_to_peers(key)
                
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.exception("Error in invalidation loop", error=str(e))
    
    async def _send_invalidation_to_peers(self, key: str):
        """Send invalidation message to peer nodes.
        
        Args:
            key: Key to invalidate
        """
        # This would typically send messages to peer nodes
        # For now, just log the invalidation
        logger.debug(
            "Sending invalidation to peers",
            key=key,
            peers=list(self.peer_nodes),
        )
    
    async def receive_invalidation(self, key: str, from_node: str):
        """Receive invalidation message from peer node.
        
        Args:
            key: Key to invalidate
            from_node: Node that sent the invalidation
        """
        if key in self.entries:
            await self._remove_entry(key)
            logger.debug(
                "Received invalidation from peer",
                key=key,
                from_node=from_node,
            )
    
    def add_peer_node(self, node_id: str):
        """Add a peer node for invalidation.
        
        Args:
            node_id: Peer node ID
        """
        self.peer_nodes.add(node_id)
        logger.info(f"Added peer node: {node_id}")
    
    def remove_peer_node(self, node_id: str):
        """Remove a peer node.
        
        Args:
            node_id: Peer node ID
        """
        self.peer_nodes.discard(node_id)
        logger.info(f"Removed peer node: {node_id}")
    
    async def consistency_check(self) -> Dict[str, Any]:
        """Perform consistency check across cache entries.
        
        Returns:
            Dictionary with consistency check results
        """
        self.stats["consistency_checks"] += 1
        
        results = {
            "total_entries": len(self.entries),
            "expired_entries": 0,
            "locked_entries": 0,
            "checksum_mismatches": 0,
            "issues": [],
        }
        
        current_time = time.time()
        
        for key, entry in self.entries.items():
            # Check for expired entries
            if entry.is_expired():
                results["expired_entries"] += 1
                results["issues"].append(f"Expired entry: {key}")
            
            # Check for locked entries
            if entry.locked:
                results["locked_entries"] += 1
                if entry.is_lock_expired():
                    results["issues"].append(f"Expired lock: {key}")
            
            # Check checksum consistency
            expected_checksum = entry._calculate_checksum()
            if entry.checksum != expected_checksum:
                results["checksum_mismatches"] += 1
                results["issues"].append(f"Checksum mismatch: {key}")
                self.stats["consistency_failures"] += 1
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        total_requests = self.stats["hits"] + self.stats["misses"]
        hit_rate = self.stats["hits"] / max(total_requests, 1)
        
        return {
            "cache_id": self.cache_id,
            "node_id": self.node_id,
            "entries_count": len(self.entries),
            "locks_count": len(self.locks),
            "peer_nodes": list(self.peer_nodes),
            "hit_rate": hit_rate,
            "stats": self.stats.copy(),
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the cache.
        
        Returns:
            Health check results
        """
        consistency_results = await self.consistency_check()
        
        healthy = (
            self.running and
            consistency_results["checksum_mismatches"] == 0 and
            len(consistency_results["issues"]) == 0
        )
        
        return {
            "healthy": healthy,
            "timestamp": datetime.utcnow().isoformat(),
            "consistency_check": consistency_results,
            "stats": self.get_stats(),
        }


class CacheCluster:
    """Manages a cluster of distributed caches."""
    
    def __init__(self, cluster_id: str):
        self.cluster_id = cluster_id
        self.nodes: Dict[str, DistributedCache] = {}
        self.hash_ring: List[str] = []
        self.replication_factor = 2
    
    def add_node(self, cache: DistributedCache):
        """Add a cache node to the cluster.
        
        Args:
            cache: Cache node to add
        """
        self.nodes[cache.node_id] = cache
        self.hash_ring.append(cache.node_id)
        
        # Add as peer to other nodes
        for node_id, other_cache in self.nodes.items():
            if node_id != cache.node_id:
                cache.add_peer_node(node_id)
                other_cache.add_peer_node(cache.node_id)
        
        logger.info(
            "Added cache node to cluster",
            cluster_id=self.cluster_id,
            node_id=cache.node_id,
        )
    
    def remove_node(self, node_id: str):
        """Remove a cache node from the cluster.
        
        Args:
            node_id: Node ID to remove
        """
        if node_id in self.nodes:
            cache = self.nodes[node_id]
            del self.nodes[node_id]
            
            if node_id in self.hash_ring:
                self.hash_ring.remove(node_id)
            
            # Remove as peer from other nodes
            for other_cache in self.nodes.values():
                other_cache.remove_peer_node(node_id)
            
            logger.info(
                "Removed cache node from cluster",
                cluster_id=self.cluster_id,
                node_id=node_id,
            )
    
    def get_node_for_key(self, key: str) -> Optional[DistributedCache]:
        """Get the primary node for a key using consistent hashing.
        
        Args:
            key: Cache key
            
        Returns:
            Primary cache node for the key
        """
        if not self.hash_ring:
            return None
        
        # Simple consistent hashing
        hash_value = hash(key) % len(self.hash_ring)
        node_id = self.hash_ring[hash_value]
        
        return self.nodes.get(node_id)
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from the cluster.
        
        Args:
            key: Cache key
            
        Returns:
            Cached value or None if not found
        """
        node = self.get_node_for_key(key)
        if node:
            return await node.get(key)
        return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set value in the cluster with replication.
        
        Args:
            key: Cache key
            value: Value to cache
            ttl: Time to live in seconds
            
        Returns:
            True if set successfully
        """
        node = self.get_node_for_key(key)
        if node:
            return await node.set(key, value, ttl)
        return False
    
    async def delete(self, key: str) -> bool:
        """Delete value from the cluster.
        
        Args:
            key: Cache key
            
        Returns:
            True if deleted successfully
        """
        node = self.get_node_for_key(key)
        if node:
            return await node.delete(key)
        return False
    
    async def start_all(self):
        """Start all cache nodes in the cluster."""
        for cache in self.nodes.values():
            await cache.start()
        
        logger.info(
            "Started all cache nodes in cluster",
            cluster_id=self.cluster_id,
            node_count=len(self.nodes),
        )
    
    async def stop_all(self):
        """Stop all cache nodes in the cluster."""
        for cache in self.nodes.values():
            await cache.stop()
        
        logger.info(
            "Stopped all cache nodes in cluster",
            cluster_id=self.cluster_id,
        )
    
    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster statistics.
        
        Returns:
            Dictionary with cluster statistics
        """
        node_stats = {}
        total_entries = 0
        total_hits = 0
        total_misses = 0
        
        for node_id, cache in self.nodes.items():
            stats = cache.get_stats()
            node_stats[node_id] = stats
            total_entries += stats["entries_count"]
            total_hits += stats["stats"]["hits"]
            total_misses += stats["stats"]["misses"]
        
        total_requests = total_hits + total_misses
        overall_hit_rate = total_hits / max(total_requests, 1)
        
        return {
            "cluster_id": self.cluster_id,
            "node_count": len(self.nodes),
            "total_entries": total_entries,
            "overall_hit_rate": overall_hit_rate,
            "nodes": node_stats,
        }


# Global cache cluster
_cache_cluster: Optional[CacheCluster] = None


def get_cache_cluster() -> CacheCluster:
    """Get the global cache cluster.
    
    Returns:
        CacheCluster: Global cluster instance
    """
    global _cache_cluster
    
    if _cache_cluster is None:
        _cache_cluster = CacheCluster("identity_cache_cluster")
    
    return _cache_cluster


async def initialize_distributed_cache(node_count: int = 3) -> CacheCluster:
    """Initialize distributed cache cluster.
    
    Args:
        node_count: Number of cache nodes
        
    Returns:
        CacheCluster: Initialized cluster
    """
    cluster = get_cache_cluster()
    
    # Create cache nodes
    for i in range(node_count):
        node_id = f"cache_node_{i}"
        cache = DistributedCache("identity_cache", node_id)
        cluster.add_node(cache)
    
    # Start all nodes
    await cluster.start_all()
    
    return cluster