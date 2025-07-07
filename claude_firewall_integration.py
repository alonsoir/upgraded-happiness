#!/usr/bin/env python3
"""
🤖 Claude Firewall Integration - Generador Inteligente de Comandos
Integra Claude para generar comandos de firewall inteligentes basados en eventos ML
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional

# Configurar logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ClaudeFirewallGenerator:
    """Generador de comandos de firewall usando Claude"""

    def __init__(self):
        self.threat_knowledge = {
            # Base de conocimiento de amenazas
            'ssh_brute_force': {
                'ports': [22],
                'patterns': ['multiple failed logins', 'brute force', 'ssh attack'],
                'response': 'rate_limit_strict',
                'duration': '24h',
                'priority': 'high'
            },
            'rdp_attack': {
                'ports': [3389],
                'patterns': ['rdp brute', 'remote desktop', 'rdp attack'],
                'response': 'block_immediate',
                'duration': '12h',
                'priority': 'high'
            },
            'web_attack': {
                'ports': [80, 443],
                'patterns': ['sql injection', 'xss', 'web exploit', 'ddos'],
                'response': 'rate_limit_web',
                'duration': '6h',
                'priority': 'medium'
            },
            'port_scan': {
                'ports': range(1, 65536),
                'patterns': ['port scan', 'reconnaissance', 'scanning'],
                'response': 'block_scanner',
                'duration': '2h',
                'priority': 'medium'
            },
            'ddos_attack': {
                'ports': 'any',
                'patterns': ['flood', 'ddos', 'volumetric'],
                'response': 'rate_limit_aggressive',
                'duration': '1h',
                'priority': 'critical'
            }
        }

    async def generate_intelligent_command(self, event_data: Dict) -> Dict:
        """
        Generar comando inteligente usando Claude (simulado)
        En tu implementación real, aquí usarías window.claude.complete
        """
        try:
            # Analizar el evento
            threat_analysis = self._analyze_threat(event_data)

            # Crear prompt para Claude
            claude_prompt = self._create_claude_prompt(event_data, threat_analysis)

            # En la implementación real, aquí llamarías a Claude:
            # claude_response = await window.claude.complete(claude_prompt)
            # command_data = json.loads(claude_response)

            # Por ahora, simulamos la respuesta de Claude
            command_data = await self._simulate_claude_response(event_data, threat_analysis)

            # Validar y enriquecer el comando
            final_command = self._enrich_command(command_data, event_data)

            logger.info(f"🤖 Comando generado para {event_data.get('source_ip')}")
            return final_command

        except Exception as e:
            logger.error(f"❌ Error generando comando: {e}")
            return self._generate_fallback_command(event_data)

    def _analyze_threat(self, event_data: Dict) -> Dict:
        """Analizar tipo de amenaza basado en el evento"""
        dest_port = event_data.get('dest_port', 0)
        description = event_data.get('description', '').lower()
        risk_score = event_data.get('risk_score', 0)
        anomaly_score = event_data.get('anomaly_score', 0)
        packet_size = event_data.get('packet_size', 0)

        # Determinar tipo de amenaza
        threat_type = 'unknown'
        confidence = 0.5

        for threat_name, threat_info in self.threat_knowledge.items():
            # Verificar puerto
            port_match = False
            if isinstance(threat_info['ports'], list):
                port_match = dest_port in threat_info['ports']
            elif isinstance(threat_info['ports'], range):
                port_match = dest_port in threat_info['ports']
            elif threat_info['ports'] == 'any':
                port_match = True

            # Verificar patrones en descripción
            pattern_match = any(pattern in description for pattern in threat_info['patterns'])

            if port_match and pattern_match:
                threat_type = threat_name
                confidence = 0.9
                break
            elif port_match:
                threat_type = threat_name
                confidence = 0.7
                break

        # Ajustar confianza basado en scores ML
        if risk_score > 0.8:
            confidence = min(confidence + 0.2, 1.0)
        if anomaly_score > 0.8:
            confidence = min(confidence + 0.1, 1.0)

        return {
            'threat_type': threat_type,
            'confidence': confidence,
            'risk_level': self._calculate_risk_level(risk_score, anomaly_score),
            'recommended_action': self.threat_knowledge.get(threat_type, {}).get('response', 'block_ip'),
            'suggested_duration': self.threat_knowledge.get(threat_type, {}).get('duration', '1h'),
            'priority': self.threat_knowledge.get(threat_type, {}).get('priority', 'medium')
        }

    def _calculate_risk_level(self, risk_score: float, anomaly_score: float) -> str:
        """Calcular nivel de riesgo combinado"""
        combined_score = (risk_score * 0.7) + (anomaly_score * 0.3)

        if combined_score >= 0.9:
            return 'critical'
        elif combined_score >= 0.8:
            return 'high'
        elif combined_score >= 0.6:
            return 'medium'
        elif combined_score >= 0.3:
            return 'low'
        else:
            return 'minimal'

    def _create_claude_prompt(self, event_data: Dict, threat_analysis: Dict) -> str:
        """Crear prompt optimizado para Claude"""
        prompt = f"""
Eres un experto en ciberseguridad que debe generar comandos de firewall para responder a amenazas detectadas por ML.

EVENTO DETECTADO:
- IP Origen: {event_data.get('source_ip')}
- IP Destino: {event_data.get('target_ip')}:{event_data.get('dest_port')}
- Protocolo: {event_data.get('protocol', 'TCP')}
- Tamaño del paquete: {event_data.get('packet_size', 0)} bytes
- Risk Score (ML): {event_data.get('risk_score', 0):.3f}
- Anomaly Score (ML): {event_data.get('anomaly_score', 0):.3f}
- Descripción: {event_data.get('description', 'No description')}
- Agente: {event_data.get('agent_id')}

ANÁLISIS AUTOMÁTICO:
- Tipo de amenaza detectada: {threat_analysis['threat_type']}
- Nivel de riesgo: {threat_analysis['risk_level']}
- Confianza del análisis: {threat_analysis['confidence']:.1%}
- Acción recomendada: {threat_analysis['recommended_action']}

CONTEXTO:
- Este evento fue detectado por modelos de ML como sospechoso
- Puerto {event_data.get('dest_port')} está siendo atacado
- Necesitamos respuesta automática e inmediata
- El firewall usa iptables en Linux

GENERA un comando de firewall JSON con esta estructura EXACTA:

{{
    "action": "TIPO_DE_ACCION",
    "target_ip": "{event_data.get('source_ip')}",
    "source_agent": "{event_data.get('agent_id')}",
    "reason": "RAZON_DETALLADA_DEL_BLOQUEO",
    "firewall_rule": {{
        "rule_type": "iptables",
        "command": "COMANDO_IPTABLES_ESPECIFICO_Y_OPTIMIZADO",
        "duration": "DURACION_APROPIADA",
        "priority": "PRIORIDAD"
    }},
    "metadata": {{
        "ml_scores": {{"A": {event_data.get('anomaly_score', 0):.3f}, "R": {event_data.get('risk_score', 0):.3f}}},
        "packet_info": "Packet from {event_data.get('source_ip')} to {event_data.get('target_ip')}:{event_data.get('dest_port')}",
        "threat_analysis": "{threat_analysis['threat_type'].upper()}",
        "confidence": "{threat_analysis['confidence']:.1%}",
        "risk_level": "{threat_analysis['risk_level']}",
        "timestamp": "{datetime.now().isoformat()}"
    }}
}}

REGLAS IMPORTANTES:
1. Para SSH (puerto 22): Usa rate limiting antes del bloqueo total
2. Para HTTP/HTTPS (80/443): Rate limiting específico para web
3. Para RDP (3389): Bloqueo inmediato
4. Para otros puertos: Bloqueo directo
5. Considera el risk_score para determinar duración
6. Risk score > 0.9 = duración 24h+
7. Risk score 0.7-0.9 = duración 6-12h
8. Risk score < 0.7 = duración 1-3h

RESPONDE SOLO CON EL JSON VÁLIDO, SIN BACKTICKS NI TEXTO ADICIONAL.
"""
        return prompt

    async def _simulate_claude_response(self, event_data: Dict, threat_analysis: Dict) -> Dict:
        """Simular respuesta de Claude (en implementación real, usar window.claude.complete)"""

        dest_port = event_data.get('dest_port', 0)
        risk_score = event_data.get('risk_score', 0)
        source_ip = event_data.get('source_ip')

        # Determinar duración basada en risk score
        if risk_score >= 0.9:
            duration = '24h'
        elif risk_score >= 0.7:
            duration = '12h'
        elif risk_score >= 0.5:
            duration = '6h'
        else:
            duration = '3h'

        # Generar comando específico por puerto
        if dest_port == 22:  # SSH
            action = "rate_limit_ssh"
            command = f"iptables -A INPUT -s {source_ip} -p tcp --dport 22 -m limit --limit 3/min --limit-burst 5 -j ACCEPT; iptables -A INPUT -s {source_ip} -p tcp --dport 22 -j DROP"
            reason = f"SSH brute force attack detected with {risk_score:.1%} risk score"

        elif dest_port in [80, 443]:  # HTTP/HTTPS
            action = "rate_limit_web"
            rate_limit = "10/min" if risk_score > 0.8 else "20/min"
            command = f"iptables -A INPUT -s {source_ip} -p tcp --dport {dest_port} -m limit --limit {rate_limit} -j ACCEPT; iptables -A INPUT -s {source_ip} -p tcp --dport {dest_port} -j DROP"
            reason = f"Web application attack detected on port {dest_port}"

        elif dest_port == 3389:  # RDP
            action = "block_rdp"
            command = f"iptables -A INPUT -s {source_ip} -p tcp --dport 3389 -j DROP"
            reason = f"RDP attack detected with {risk_score:.1%} risk score"

        else:  # Otros puertos
            action = "block_ip"
            command = f"iptables -A INPUT -s {source_ip} -j DROP"
            reason = f"Suspicious network activity on port {dest_port} with {risk_score:.1%} risk score"

        # Ajustar prioridad
        if risk_score >= 0.9:
            priority = "critical"
        elif risk_score >= 0.8:
            priority = "high"
        elif risk_score >= 0.6:
            priority = "medium"
        else:
            priority = "low"

        return {
            "action": action,
            "target_ip": source_ip,
            "source_agent": event_data.get('agent_id'),
            "reason": reason,
            "firewall_rule": {
                "rule_type": "iptables",
                "command": command,
                "duration": duration,
                "priority": priority
            },
            "metadata": {
                "ml_scores": {
                    "A": event_data.get('anomaly_score', 0),
                    "R": event_data.get('risk_score', 0)
                },
                "packet_info": f"Packet from {source_ip} to {event_data.get('target_ip')}:{dest_port}",
                "threat_analysis": threat_analysis['threat_type'].upper(),
                "confidence": f"{threat_analysis['confidence']:.1%}",
                "risk_level": threat_analysis['risk_level'],
                "timestamp": datetime.now().isoformat()
            }
        }

    def _enrich_command(self, command_data: Dict, event_data: Dict) -> Dict:
        """Enriquecer comando con información adicional"""
        # Añadir metadatos del sistema
        enriched_command = {
            **command_data,
            "command_id": f"claude_fw_{int(datetime.now().timestamp() * 1000)}",
            "generated_by": "claude_firewall_generator",
            "generation_timestamp": datetime.now().isoformat(),
            "event_reference": event_data.get('event_id'),
            "dashboard_version": "2.0_claude_enhanced",
            "generator_confidence": command_data.get('metadata', {}).get('confidence', '85%')
        }

        # Validar campos requeridos
        required_fields = ['action', 'target_ip', 'source_agent', 'firewall_rule']
        for field in required_fields:
            if field not in enriched_command:
                logger.warning(f"⚠️ Campo requerido faltante: {field}")
                return self._generate_fallback_command(event_data)

        return enriched_command

    def _generate_fallback_command(self, event_data: Dict) -> Dict:
        """Generar comando de fallback si Claude falla"""
        logger.warning("🔄 Generando comando de fallback")

        return {
            "action": "block_ip_fallback",
            "target_ip": event_data.get('source_ip', 'unknown'),
            "source_agent": event_data.get('agent_id', 'unknown'),
            "reason": "Fallback command due to ML detection error",
            "firewall_rule": {
                "rule_type": "iptables",
                "command": f"iptables -A INPUT -s {event_data.get('source_ip', '0.0.0.0')} -j DROP",
                "duration": "1h",
                "priority": "medium"
            },
            "metadata": {
                "ml_scores": {
                    "A": event_data.get('anomaly_score', 0),
                    "R": event_data.get('risk_score', 0)
                },
                "packet_info": "Fallback command generated",
                "threat_analysis": "UNKNOWN_FALLBACK",
                "confidence": "50%",
                "risk_level": "medium",
                "timestamp": datetime.now().isoformat()
            },
            "command_id": f"fallback_fw_{int(datetime.now().timestamp() * 1000)}",
            "generated_by": "fallback_generator",
            "generation_timestamp": datetime.now().isoformat()
        }

    def get_threat_statistics(self) -> Dict:
        """Obtener estadísticas de tipos de amenazas"""
        return {
            "supported_threats": list(self.threat_knowledge.keys()),
            "total_threat_types": len(self.threat_knowledge),
            "generator_version": "2.0_claude_enhanced",
            "last_updated": datetime.now().isoformat()
        }


# Función de utilidad para integración con el dashboard
async def generate_claude_firewall_command(event_data: Dict) -> Dict:
    """
    Función principal para generar comandos usando Claude
    Usar esta función desde el dashboard
    """
    generator = ClaudeFirewallGenerator()
    return await generator.generate_intelligent_command(event_data)


# Ejemplo de uso y testing
async def test_claude_integration():
    """Función de test para validar la integración"""
    print("🧪 TESTING CLAUDE FIREWALL INTEGRATION")
    print("=" * 50)

    # Eventos de prueba
    test_events = [
        {
            "event_id": "evt_test_ssh",
            "source_ip": "192.168.1.100",
            "target_ip": "10.0.0.1",
            "dest_port": 22,
            "protocol": "TCP",
            "risk_score": 0.85,
            "anomaly_score": 0.72,
            "packet_size": 1024,
            "description": "Multiple failed SSH login attempts",
            "agent_id": "agent_test_1"
        },
        {
            "event_id": "evt_test_web",
            "source_ip": "203.0.113.50",
            "target_ip": "10.0.0.2",
            "dest_port": 80,
            "protocol": "TCP",
            "risk_score": 0.75,
            "anomaly_score": 0.68,
            "packet_size": 2048,
            "description": "SQL injection attempt detected",
            "agent_id": "agent_test_2"
        },
        {
            "event_id": "evt_test_rdp",
            "source_ip": "198.51.100.25",
            "target_ip": "10.0.0.3",
            "dest_port": 3389,
            "protocol": "TCP",
            "risk_score": 0.92,
            "anomaly_score": 0.89,
            "packet_size": 512,
            "description": "RDP brute force attack",
            "agent_id": "agent_test_3"
        }
    ]

    generator = ClaudeFirewallGenerator()

    for i, event in enumerate(test_events, 1):
        print(f"\n🔍 Test {i}: {event['description']}")
        print(f"   Puerto: {event['dest_port']}")
        print(f"   Risk Score: {event['risk_score']:.2f}")

        # Generar comando
        command = await generator.generate_intelligent_command(event)

        print(f"   ✅ Comando generado:")
        print(f"      Acción: {command['action']}")
        print(f"      IP Objetivo: {command['target_ip']}")
        print(f"      Duración: {command['firewall_rule']['duration']}")
        print(f"      Prioridad: {command['firewall_rule']['priority']}")
        print(f"      Confianza: {command['metadata']['confidence']}")
        print(f"      Comando: {command['firewall_rule']['command'][:60]}...")

    print(f"\n📊 Estadísticas del generador:")
    stats = generator.get_threat_statistics()
    print(f"   Tipos de amenazas soportadas: {stats['total_threat_types']}")
    print(f"   Versión: {stats['generator_version']}")

    print("\n✅ Testing completado")


if __name__ == "__main__":
    # Ejecutar tests
    asyncio.run(test_claude_integration())