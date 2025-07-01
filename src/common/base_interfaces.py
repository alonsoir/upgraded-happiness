"""
Base interfaces and common types for the upgraded-happiness protocol research framework.
"""

import asyncio
import random
import string
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Union


class CompressionAlgorithm(Enum):
    """Supported compression algorithms"""

    NONE = "none"
    LZ4 = "lz4"
    ZSTD = "zstd"
    SNAPPY = "snappy"
    BROTLI = "brotli"


class EncryptionAlgorithm(Enum):
    """Supported encryption algorithms"""

    NONE = "none"
    CHACHA20 = "chacha20"
    AES_GCM = "aes_gcm"
    XCHACHA20 = "xchacha20"


class EventType(Enum):
    """SCADA event types for research"""

    HEARTBEAT = "heartbeat"
    SECURITY_ALERT = "security_alert"
    NETWORK_ANOMALY = "network_anomaly"
    PROTOCOL_VIOLATION = "protocol_violation"
    PERFORMANCE_ISSUE = "performance_issue"
    SYSTEM_STATUS = "system_status"
    AGENT_START = "agent_start"
    AGENT_STOP = "agent_stop"
    CONFIG_CHANGE = "config_change"
    SCADA_ALARM = "scada_alarm"
    MODBUS_EVENT = "modbus_event"
    DNP3_EVENT = "dnp3_event"


class Severity(Enum):
    """Event severity levels"""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class EventData:
    """Base event data structure for research"""

    event_id: str
    timestamp: int
    event_type: EventType
    severity: Severity
    source_ip: str
    target_ip: str
    properties: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SerializationMetrics:
    """Metrics collected during serialization/deserialization"""

    serialization_time_ns: int = 0
    deserialization_time_ns: int = 0
    original_size_bytes: int = 0
    compressed_size_bytes: int = 0
    final_size_bytes: int = 0
    compression_ratio: float = 1.0
    memory_usage_bytes: int = 0
    cpu_time_ns: int = 0

    @property
    def total_time_ns(self) -> int:
        return self.serialization_time_ns + self.deserialization_time_ns

    @property
    def throughput_mbps(self) -> float:
        """Calculate throughput in MB/s"""
        if self.total_time_ns == 0:
            return 0.0

        # Convert bytes to megabytes and nanoseconds to seconds
        mb = self.original_size_bytes / (1024 * 1024)
        seconds = self.total_time_ns / 1_000_000_000

        return mb / seconds if seconds > 0 else 0.0


class EventSerializer(ABC):
    """Abstract base class for event serializers"""

    def __init__(
        self,
        compression: Optional[CompressionAlgorithm] = None,
        encryption: Optional[EncryptionAlgorithm] = None,
        encryption_key: Optional[bytes] = None,
    ):
        self.compression = compression or CompressionAlgorithm.NONE
        self.encryption = encryption or EncryptionAlgorithm.NONE
        self.encryption_key = encryption_key

    @abstractmethod
    async def serialize(
        self,
        event: Union[EventData, Dict[str, Any]],
        compression: Optional[CompressionAlgorithm] = None,
        encryption: Optional[EncryptionAlgorithm] = None,
    ) -> bytes:
        """Serialize an event to bytes"""
        pass

    @abstractmethod
    async def deserialize(
        self,
        data: bytes,
        compression: Optional[CompressionAlgorithm] = None,
        encryption: Optional[EncryptionAlgorithm] = None,
    ) -> Union[EventData, Dict[str, Any]]:
        """Deserialize bytes back to an event"""
        pass

    def get_metrics(self) -> SerializationMetrics:
        """Get the latest serialization metrics"""
        return getattr(self, "_last_metrics", SerializationMetrics())


class ResearchDataGenerator:
    """Generate synthetic data for research purposes"""

    def __init__(self, seed: Optional[int] = None):
        if seed is not None:
            random.seed(seed)

    def generate_event_data(
        self,
        event_type: EventType = EventType.HEARTBEAT,
        severity: Severity = Severity.INFO,
    ) -> EventData:
        """Generate a single synthetic event"""

        timestamp = int(time.time() * 1_000_000_000)  # nanoseconds
        event_id = f"evt_{random.randint(100000, 999999)}"

        # Generate random IPs
        source_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
        target_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"

        # Generate properties based on event type
        properties = self._generate_properties_for_type(event_type)

        # Generate metadata
        metadata = {
            "node_id": f"node_{random.randint(1, 100)}",
            "agent_version": f"1.{random.randint(0, 9)}.{random.randint(0, 9)}",
            "sequence_number": random.randint(1, 10000),
            "batch_id": f"batch_{random.randint(1000, 9999)}",
        }

        return EventData(
            event_id=event_id,
            timestamp=timestamp,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            target_ip=target_ip,
            properties=properties,
            metadata=metadata,
        )

    def _generate_properties_for_type(self, event_type: EventType) -> Dict[str, Any]:
        """Generate realistic properties based on event type"""

        base_properties = {
            "session_id": f"sess_{''.join(random.choices(string.ascii_lowercase + string.digits, k=8))}",
            "protocol": random.choice(["modbus", "dnp3", "iec61850", "bacnet"]),
            "device_id": f"dev_{random.randint(1, 500)}",
        }

        if event_type == EventType.SECURITY_ALERT:
            base_properties.update(
                {
                    "attack_type": random.choice(
                        [
                            "brute_force",
                            "sql_injection",
                            "buffer_overflow",
                            "man_in_middle",
                        ]
                    ),
                    "confidence_score": round(random.uniform(0.1, 1.0), 3),
                    "indicators": [
                        f"indicator_{i}" for i in range(random.randint(1, 5))
                    ],
                    "signature": f"sig_{random.randint(1000, 9999)}",
                }
            )

        elif event_type == EventType.NETWORK_ANOMALY:
            base_properties.update(
                {
                    "bandwidth_usage": random.randint(50, 1000),
                    "packet_loss_percent": round(random.uniform(0, 5), 2),
                    "latency_ms": round(random.uniform(1, 100), 2),
                    "connection_count": random.randint(1, 100),
                }
            )

        elif event_type == EventType.SCADA_ALARM:
            base_properties.update(
                {
                    "alarm_code": random.randint(1000, 9999),
                    "alarm_text": random.choice(
                        [
                            "Temperature threshold exceeded",
                            "Pressure sensor failure",
                            "Communication timeout",
                            "Unauthorized access attempt",
                        ]
                    ),
                    "value": round(random.uniform(0, 1000), 2),
                    "threshold": round(random.uniform(500, 800), 2),
                    "unit": random.choice(["celsius", "psi", "volts", "amps"]),
                }
            )

        elif event_type == EventType.PERFORMANCE_ISSUE:
            base_properties.update(
                {
                    "cpu_percent": round(random.uniform(70, 100), 1),
                    "memory_percent": round(random.uniform(80, 100), 1),
                    "disk_usage_percent": round(random.uniform(85, 100), 1),
                    "response_time_ms": round(random.uniform(500, 5000), 1),
                }
            )

        # Add some random nested data for complexity
        base_properties["nested_data"] = {
            "level1": {
                "level2": {
                    "values": [
                        random.randint(1, 100) for _ in range(random.randint(5, 15))
                    ],
                    "description": f"Random data for testing - {''.join(random.choices(string.ascii_letters, k=20))}",
                }
            }
        }

        return base_properties

    def generate_security_events(self, count: int) -> List[EventData]:
        """Generate multiple security events for testing"""
        return [
            self.generate_event_data(
                event_type=EventType.SECURITY_ALERT,
                severity=random.choice(list(Severity)),
            )
            for _ in range(count)
        ]

    def generate_mixed_events(self, count: int) -> List[EventData]:
        """Generate mixed event types for comprehensive testing"""
        events = []
        event_types = list(EventType)
        severities = list(Severity)

        for _ in range(count):
            event_type = random.choice(event_types)
            severity = random.choice(severities)
            events.append(self.generate_event_data(event_type, severity))

        return events

    async def generate_event_stream(
        self, events_per_second: int, duration_seconds: int
    ) -> List[EventData]:
        """Generate a stream of events over time"""
        events = []
        total_events = events_per_second * duration_seconds
        interval = 1.0 / events_per_second

        for i in range(total_events):
            event = self.generate_event_data(
                event_type=random.choice(list(EventType)),
                severity=random.choice(list(Severity)),
            )
            events.append(event)

            # Simulate real-time generation
            if i % events_per_second == 0 and i > 0:
                await asyncio.sleep(0.001)  # Small delay to prevent blocking

        return events


# Utility functions
def measure_time_ns():
    """Get current time in nanoseconds for precise measurements"""
    return time.perf_counter_ns()


def format_bytes(size_bytes: int) -> str:
    """Format bytes in human readable format"""
    if size_bytes == 0:
        return "0 B"

    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math

    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


def format_time_ns(time_ns: int) -> str:
    """Format nanoseconds in human readable format"""
    if time_ns < 1000:
        return f"{time_ns} ns"
    elif time_ns < 1_000_000:
        return f"{time_ns / 1000:.1f} μs"
    elif time_ns < 1_000_000_000:
        return f"{time_ns / 1_000_000:.1f} ms"
    else:
        return f"{time_ns / 1_000_000_000:.2f} s"


# Export main classes and functions
__all__ = [
    "CompressionAlgorithm",
    "EncryptionAlgorithm",
    "EventType",
    "Severity",
    "EventData",
    "SerializationMetrics",
    "EventSerializer",
    "ResearchDataGenerator",
    "measure_time_ns",
    "format_bytes",
    "format_time_ns",
]
