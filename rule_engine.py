#!/usr/bin/env python3
"""
Motor de Reglas Determinísticas para Upgraded-Happiness
Análisis local, costo cero, alta eficiencia, decisiones transparentes.

Este es el corazón del sistema de recomendaciones de firewall.
"""

import time
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
from datetime import datetime, timedelta
import ipaddress

logger = logging.getLogger(__name__)


@dataclass
class FirewallRecommendation:
    """Recomendación de acción de firewall"""
    action: str  # BLOCK_IP, RATE_LIMIT, ALLOW, etc.
    target_ip: str  # IP objetivo
    target_port: Optional[int]  # Puerto objetivo (opcional)
    reason: str  # Razón humana legible
    priority: str  # LOW, MEDIUM, HIGH, CRITICAL
    duration_seconds: int  # Duración de la regla
    confidence: float  # Confianza en la recomendación (0-1)
    rule_triggered: str  # Nombre de la regla que se activó
    additional_context: Dict  # Información adicional


@dataclass
class EventSummary:
    """Resumen de eventos por IP para análisis temporal"""
    ip: str
    connection_count: int
    unique_ports: set
    first_seen: float
    last_seen: float
    total_bytes: int
    protocols: set
    anomaly_scores: List[float]


class ThreatIntelligence:
    """Base de conocimiento de amenazas básica"""

    def __init__(self):
        # Puertos sensibles en entornos SCADA
        self.sensitive_ports = {
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            443: "HTTPS",
            502: "Modbus TCP",
            503: "Modbus RTU",
            1911: "Niagara Fox",
            2222: "EtherNet/IP",
            4840: "OPC UA",
            9600: "FactoryTalk",
            20000: "DNP3",
            44818: "EtherNet/IP"
        }

        # Rangos de IP típicamente problemáticos
        self.suspicious_ranges = [
            "10.0.0.0/8",  # A veces usado por atacantes
            "172.16.0.0/12",  # Redes privadas mal configuradas
            "192.168.0.0/16",  # Depende del contexto
        ]

        # Países con alta actividad maliciosa (configurable)
        self.high_risk_countries = ["CN", "RU", "KP", "IR"]

        # Patrones de User-Agent sospechosos
        self.suspicious_patterns = [
            "nmap", "masscan", "zmap", "shodan", "censys",
            "python-requests", "curl", "wget"
        ]


class RuleEngine:
    """Motor principal de reglas determinísticas"""

    def __init__(self, config_file: Optional[str] = None):
        self.config = self._load_config(config_file)
        self.threat_intel = ThreatIntelligence()

        # Ventanas deslizantes para análisis temporal
        self.connection_windows = defaultdict(lambda: deque(maxlen=1000))
        self.port_scan_windows = defaultdict(lambda: deque(maxlen=100))
        self.anomaly_history = defaultdict(lambda: deque(maxlen=50))

        # Cache de eventos por IP
        self.ip_summaries = {}

        # Estadísticas del motor
        self.stats = {
            'events_processed': 0,
            'recommendations_generated': 0,
            'rules_triggered': defaultdict(int)
        }

        logger.info("RuleEngine initialized with config: %s", self.config['name'])

    def _load_config(self, config_file: Optional[str]) -> Dict:
        """Carga configuración o usa valores por defecto"""
        default_config = {
            'name': 'default_rule_engine',
            'rate_limit_threshold': 50,  # conexiones por minuto
            'rate_limit_window': 60,  # ventana en segundos
            'port_scan_threshold': 10,  # puertos únicos por minuto
            'port_scan_window': 60,  # ventana en segundos
            'anomaly_score_critical': 0.9,  # umbral crítico ML
            'anomaly_score_high': 0.7,  # umbral alto ML
            'anomaly_score_medium': 0.5,  # umbral medio ML
            'blacklist_duration': 3600,  # 1 hora
            'rate_limit_duration': 1800,  # 30 minutos
            'temp_block_duration': 300,  # 5 minutos
            'min_confidence': 0.7,  # confianza mínima para recomendar
            'enable_geoblocking': False,  # bloqueo geográfico
            'enable_port_protection': True,  # protección puertos sensibles
            'enable_anomaly_detection': True,  # detección ML
            'enable_rate_limiting': True,  # rate limiting
            'enable_port_scan_detection': True,  # detección port scanning
        }

        if config_file:
            try:
                with open(config_file, 'r') as f:
                    custom_config = json.load(f)
                default_config.update(custom_config)
                logger.info(f"Loaded custom config from {config_file}")
            except Exception as e:
                logger.warning(f"Could not load config {config_file}: {e}")

        return default_config

    def analyze_event(self, event: Dict) -> List[FirewallRecommendation]:
        """Análisis principal de un evento"""
        self.stats['events_processed'] += 1
        recommendations = []

        try:
            # Actualizar ventanas deslizantes
            self._update_tracking_windows(event)

            # Aplicar reglas en orden de prioridad
            if self.config['enable_anomaly_detection']:
                recommendations.extend(self._rule_anomaly_detection(event))

            if self.config['enable_rate_limiting']:
                recommendations.extend(self._rule_rate_limiting(event))

            if self.config['enable_port_scan_detection']:
                recommendations.extend(self._rule_port_scan_detection(event))

            if self.config['enable_port_protection']:
                recommendations.extend(self._rule_sensitive_port_protection(event))

            if self.config['enable_geoblocking']:
                recommendations.extend(self._rule_geographic_blocking(event))

            # Filtrar por confianza mínima
            recommendations = [r for r in recommendations
                               if r.confidence >= self.config['min_confidence']]

            # Evitar duplicados y priorizar
            recommendations = self._prioritize_recommendations(recommendations)

            # Actualizar estadísticas
            self.stats['recommendations_generated'] += len(recommendations)
            for rec in recommendations:
                self.stats['rules_triggered'][rec.rule_triggered] += 1

            return recommendations

        except Exception as e:
            logger.error(f"Error analyzing event {event.get('event_id', 'unknown')}: {e}")
            return []

    def _update_tracking_windows(self, event: Dict):
        """Actualiza las ventanas deslizantes para análisis temporal"""
        current_time = time.time()
        source_ip = event.get('source_ip', '')

        if not source_ip:
            return

        # Ventana de conexiones
        self.connection_windows[source_ip].append({
            'timestamp': current_time,
            'dest_port': event.get('dest_port', 0),
            'bytes': event.get('packet_size', 0),
            'protocol': event.get('protocol', 'unknown')
        })

        # Ventana de port scanning
        dest_port = event.get('dest_port', 0)
        if dest_port > 0:
            self.port_scan_windows[source_ip].append({
                'timestamp': current_time,
                'port': dest_port
            })

        # Historial de anomalías
        anomaly_score = event.get('anomaly_score', 0.0)
        if anomaly_score > 0:
            self.anomaly_history[source_ip].append({
                'timestamp': current_time,
                'score': anomaly_score
            })

        # Actualizar resumen de IP
        self._update_ip_summary(source_ip, event, current_time)

    def _update_ip_summary(self, ip: str, event: Dict, timestamp: float):
        """Actualiza el resumen de actividad por IP"""
        if ip not in self.ip_summaries:
            self.ip_summaries[ip] = EventSummary(
                ip=ip,
                connection_count=0,
                unique_ports=set(),
                first_seen=timestamp,
                last_seen=timestamp,
                total_bytes=0,
                protocols=set(),
                anomaly_scores=[]
            )

        summary = self.ip_summaries[ip]
        summary.connection_count += 1
        summary.last_seen = timestamp
        summary.total_bytes += event.get('packet_size', 0)

        if event.get('dest_port', 0) > 0:
            summary.unique_ports.add(event['dest_port'])

        if event.get('protocol'):
            summary.protocols.add(event['protocol'])

        if event.get('anomaly_score', 0) > 0:
            summary.anomaly_scores.append(event['anomaly_score'])

    def _rule_anomaly_detection(self, event: Dict) -> List[FirewallRecommendation]:
        """Regla: Detección basada en puntuación de anomalía ML"""
        recommendations = []
        anomaly_score = event.get('anomaly_score', 0.0)
        source_ip = event.get('source_ip', '')

        if not source_ip or anomaly_score <= 0:
            return recommendations

        # Anomalía crítica
        if anomaly_score >= self.config['anomaly_score_critical']:
            recommendations.append(FirewallRecommendation(
                action='BLOCK_IP',
                target_ip=source_ip,
                target_port=None,
                reason=f'Anomalía crítica detectada (score: {anomaly_score:.3f})',
                priority='CRITICAL',
                duration_seconds=self.config['blacklist_duration'],
                confidence=min(anomaly_score, 1.0),
                rule_triggered='anomaly_critical',
                additional_context={
                    'anomaly_score': anomaly_score,
                    'threshold': self.config['anomaly_score_critical']
                }
            ))

        # Anomalía alta
        elif anomaly_score >= self.config['anomaly_score_high']:
            recommendations.append(FirewallRecommendation(
                action='RATE_LIMIT',
                target_ip=source_ip,
                target_port=None,
                reason=f'Anomalía alta detectada (score: {anomaly_score:.3f})',
                priority='HIGH',
                duration_seconds=self.config['rate_limit_duration'],
                confidence=anomaly_score * 0.8,  # Slightly lower confidence
                rule_triggered='anomaly_high',
                additional_context={
                    'anomaly_score': anomaly_score,
                    'threshold': self.config['anomaly_score_high']
                }
            ))

        # Anomalía media con historial
        elif anomaly_score >= self.config['anomaly_score_medium']:
            # Verificar historial reciente
            recent_anomalies = [
                a for a in self.anomaly_history[source_ip]
                if time.time() - a['timestamp'] < 300  # últimos 5 minutos
            ]

            if len(recent_anomalies) >= 3:  # 3+ anomalías en 5 minutos
                recommendations.append(FirewallRecommendation(
                    action='RATE_LIMIT',
                    target_ip=source_ip,
                    target_port=None,
                    reason=f'Múltiples anomalías medias (últimas: {len(recent_anomalies)})',
                    priority='MEDIUM',
                    duration_seconds=self.config['temp_block_duration'],
                    confidence=0.7,
                    rule_triggered='anomaly_repeated',
                    additional_context={
                        'recent_anomalies': len(recent_anomalies),
                        'current_score': anomaly_score
                    }
                ))

        return recommendations

    def _rule_rate_limiting(self, event: Dict) -> List[FirewallRecommendation]:
        """Regla: Rate limiting por exceso de conexiones"""
        recommendations = []
        source_ip = event.get('source_ip', '')

        if not source_ip:
            return recommendations

        # Contar conexiones en la ventana de tiempo
        current_time = time.time()
        window_start = current_time - self.config['rate_limit_window']

        recent_connections = [
            conn for conn in self.connection_windows[source_ip]
            if conn['timestamp'] >= window_start
        ]

        connection_count = len(recent_connections)

        if connection_count >= self.config['rate_limit_threshold']:
            # Calcular confianza basada en qué tanto se excede el umbral
            excess_ratio = connection_count / self.config['rate_limit_threshold']
            confidence = min(0.6 + (excess_ratio - 1) * 0.3, 1.0)

            recommendations.append(FirewallRecommendation(
                action='RATE_LIMIT',
                target_ip=source_ip,
                target_port=None,
                reason=f'Exceso de conexiones: {connection_count} en {self.config["rate_limit_window"]}s',
                priority='MEDIUM' if excess_ratio < 2 else 'HIGH',
                duration_seconds=self.config['rate_limit_duration'],
                confidence=confidence,
                rule_triggered='rate_limit_exceeded',
                additional_context={
                    'connection_count': connection_count,
                    'threshold': self.config['rate_limit_threshold'],
                    'window_seconds': self.config['rate_limit_window'],
                    'excess_ratio': excess_ratio
                }
            ))

        return recommendations

    def _rule_port_scan_detection(self, event: Dict) -> List[FirewallRecommendation]:
        """Regla: Detección de escaneo de puertos"""
        recommendations = []
        source_ip = event.get('source_ip', '')

        if not source_ip:
            return recommendations

        # Contar puertos únicos en la ventana de tiempo
        current_time = time.time()
        window_start = current_time - self.config['port_scan_window']

        recent_ports = {
            scan['port'] for scan in self.port_scan_windows[source_ip]
            if scan['timestamp'] >= window_start and scan['port'] > 0
        }

        unique_port_count = len(recent_ports)

        if unique_port_count >= self.config['port_scan_threshold']:
            # Confianza alta para port scanning
            confidence = min(0.8 + (unique_port_count - self.config['port_scan_threshold']) * 0.02, 1.0)

            # Prioridad basada en si incluye puertos sensibles
            sensitive_ports_scanned = recent_ports.intersection(self.threat_intel.sensitive_ports.keys())
            priority = 'CRITICAL' if sensitive_ports_scanned else 'HIGH'

            recommendations.append(FirewallRecommendation(
                action='BLOCK_IP',
                target_ip=source_ip,
                target_port=None,
                reason=f'Escaneo de puertos detectado: {unique_port_count} puertos únicos',
                priority=priority,
                duration_seconds=self.config['blacklist_duration'],
                confidence=confidence,
                rule_triggered='port_scan_detected',
                additional_context={
                    'unique_ports_scanned': unique_port_count,
                    'threshold': self.config['port_scan_threshold'],
                    'sensitive_ports_included': list(sensitive_ports_scanned),
                    'all_ports_scanned': list(recent_ports)
                }
            ))

        return recommendations

    def _rule_sensitive_port_protection(self, event: Dict) -> List[FirewallRecommendation]:
        """Regla: Protección de puertos sensibles"""
        recommendations = []
        source_ip = event.get('source_ip', '')
        dest_port = event.get('dest_port', 0)

        if not source_ip or dest_port <= 0:
            return recommendations

        # Verificar si es un puerto sensible
        if dest_port in self.threat_intel.sensitive_ports:
            port_name = self.threat_intel.sensitive_ports[dest_port]

            # Verificar si la IP ya ha intentado múltiples puertos sensibles
            summary = self.ip_summaries.get(source_ip)
            if summary:
                sensitive_ports_accessed = summary.unique_ports.intersection(
                    self.threat_intel.sensitive_ports.keys()
                )

                # Si accede a múltiples puertos sensibles, es más sospechoso
                if len(sensitive_ports_accessed) >= 2:
                    recommendations.append(FirewallRecommendation(
                        action='BLOCK_IP',
                        target_ip=source_ip,
                        target_port=None,
                        reason=f'Acceso múltiple a puertos sensibles: {len(sensitive_ports_accessed)} puertos',
                        priority='HIGH',
                        duration_seconds=self.config['blacklist_duration'],
                        confidence=0.8,
                        rule_triggered='multiple_sensitive_ports',
                        additional_context={
                            'sensitive_ports_accessed': list(sensitive_ports_accessed),
                            'current_port': dest_port,
                            'current_port_name': port_name
                        }
                    ))
                else:
                    # Primer acceso a puerto sensible - rate limit
                    recommendations.append(FirewallRecommendation(
                        action='RATE_LIMIT',
                        target_ip=source_ip,
                        target_port=dest_port,
                        reason=f'Acceso a puerto sensible: {port_name} ({dest_port})',
                        priority='MEDIUM',
                        duration_seconds=self.config['temp_block_duration'],
                        confidence=0.7,
                        rule_triggered='sensitive_port_access',
                        additional_context={
                            'port': dest_port,
                            'port_name': port_name,
                            'first_access': len(sensitive_ports_accessed) == 0
                        }
                    ))

        return recommendations

    def _rule_geographic_blocking(self, event: Dict) -> List[FirewallRecommendation]:
        """Regla: Bloqueo geográfico (placeholder)"""
        recommendations = []
        # Esta regla requeriría integración con base de datos GeoIP
        # Por ahora es un placeholder

        # TODO: Implementar cuando tengamos GeoIP database
        # source_ip = event.get('source_ip', '')
        # country_code = geoip_lookup(source_ip)
        # if country_code in self.threat_intel.high_risk_countries:
        #     recommendations.append(...)

        return recommendations

    def _prioritize_recommendations(self, recommendations: List[FirewallRecommendation]) -> List[
        FirewallRecommendation]:
        """Prioriza y elimina duplicados de recomendaciones"""
        if not recommendations:
            return []

        # Agrupar por IP objetivo
        by_ip = defaultdict(list)
        for rec in recommendations:
            by_ip[rec.target_ip].append(rec)

        # Para cada IP, tomar la recomendación de mayor prioridad
        priority_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        final_recommendations = []

        for ip, ip_recommendations in by_ip.items():
            # Ordenar por prioridad y confianza
            ip_recommendations.sort(
                key=lambda r: (priority_order.get(r.priority, 0), r.confidence),
                reverse=True
            )

            # Tomar la mejor recomendación
            best_rec = ip_recommendations[0]

            # Si hay múltiples reglas críticas, combinar contexto
            if len(ip_recommendations) > 1:
                all_rules = [r.rule_triggered for r in ip_recommendations]
                best_rec.additional_context['multiple_rules_triggered'] = all_rules
                best_rec.reason += f" (múltiples reglas: {len(all_rules)})"

            final_recommendations.append(best_rec)

        return final_recommendations

    def get_statistics(self) -> Dict:
        """Retorna estadísticas del motor de reglas"""
        return {
            'events_processed': self.stats['events_processed'],
            'recommendations_generated': self.stats['recommendations_generated'],
            'rules_triggered': dict(self.stats['rules_triggered']),
            'active_ips_tracked': len(self.ip_summaries),
            'config': self.config
        }

    def get_ip_summary(self, ip: str) -> Optional[Dict]:
        """Retorna resumen de actividad para una IP específica"""
        summary = self.ip_summaries.get(ip)
        if summary:
            return asdict(summary)
        return None


# Función de utilidad para testing
def create_test_event(source_ip: str, dest_port: int, anomaly_score: float = 0.0) -> Dict:
    """Crea un evento de prueba"""
    return {
        'event_id': f'test_{int(time.time())}',
        'timestamp': int(time.time() * 1000),
        'source_ip': source_ip,
        'target_ip': '192.168.1.10',
        'dest_port': dest_port,
        'src_port': 12345,
        'packet_size': 64,
        'anomaly_score': anomaly_score,
        'protocol': 'TCP',
        'event_type': 'NETWORK_TRAFFIC'
    }


def main():
    """Función de testing del motor de reglas"""
    import time

    # Configurar logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Crear motor de reglas
    engine = RuleEngine()

    print("🧠 Testing Rule Engine - Upgraded Happiness")
    print("=" * 50)

    # Test 1: Anomalía crítica
    print("\n1️⃣ Test: Anomalía crítica")
    event1 = create_test_event('10.0.0.100', 22, 0.95)
    recommendations = engine.analyze_event(event1)
    for rec in recommendations:
        print(f"   🚨 {rec.action} {rec.target_ip} - {rec.reason} ({rec.priority})")

    # Test 2: Port scanning
    print("\n2️⃣ Test: Port scanning")
    for port in [22, 23, 80, 443, 502, 1911, 2222, 4840]:
        event = create_test_event('192.168.1.200', port, 0.3)
        engine.analyze_event(event)
        time.sleep(0.1)  # Simular tiempo entre conexiones

    # El último evento debería triggear port scan detection
    recommendations = engine.analyze_event(create_test_event('192.168.1.200', 9999, 0.3))
    for rec in recommendations:
        print(f"   🔍 {rec.action} {rec.target_ip} - {rec.reason} ({rec.priority})")

    # Test 3: Rate limiting
    print("\n3️⃣ Test: Rate limiting")
    for i in range(55):  # Exceder threshold de 50
        event = create_test_event('172.16.0.50', 80, 0.1)
        recommendations = engine.analyze_event(event)

    for rec in recommendations:
        print(f"   ⏰ {rec.action} {rec.target_ip} - {rec.reason} ({rec.priority})")

    # Test 4: Puertos sensibles
    print("\n4️⃣ Test: Puertos sensibles")
    event4 = create_test_event('203.0.113.100', 502, 0.4)  # Modbus
    recommendations = engine.analyze_event(event4)
    for rec in recommendations:
        print(f"   🛡️ {rec.action} {rec.target_ip} - {rec.reason} ({rec.priority})")

    # Estadísticas finales
    print("\n📊 Estadísticas finales:")
    stats = engine.get_statistics()
    print(f"   Eventos procesados: {stats['events_processed']}")
    print(f"   Recomendaciones generadas: {stats['recommendations_generated']}")
    print(f"   IPs rastreadas: {stats['active_ips_tracked']}")
    print(f"   Reglas activadas: {stats['rules_triggered']}")


if __name__ == "__main__":
    main()