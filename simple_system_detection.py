#!/usr/bin/env python3
"""
Detección simple y eficiente de sistema operativo y firewall.
Version simplificada sin dependencias complejas.
"""

import platform
import subprocess
import shutil
import socket
import uuid
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class SimpleSystemDetector:
    """Detector ligero de sistema operativo y firewall"""

    def __init__(self):
        self._os_info = None
        self._firewall_info = None
        self._node_id = None

    @property
    def os_info(self) -> Dict[str, str]:
        """Información del sistema operativo (cached)"""
        if self._os_info is None:
            self._os_info = self._detect_os()
        return self._os_info

    @property
    def firewall_info(self) -> Dict[str, str]:
        """Información del firewall (cached)"""
        if self._firewall_info is None:
            self._firewall_info = self._detect_firewall()
        return self._firewall_info

    @property
    def node_id(self) -> str:
        """ID único del nodo (cached)"""
        if self._node_id is None:
            self._node_id = self._generate_node_id()
        return self._node_id

    def _detect_os(self) -> Dict[str, str]:
        """Detecta información básica del OS"""
        try:
            system = platform.system()

            if system == "Linux":
                return self._detect_linux()
            elif system == "Windows":
                return self._detect_windows()
            elif system == "Darwin":
                return self._detect_macos()
            else:
                return {
                    'name': system,
                    'version': platform.release(),
                    'family': 'unknown',
                    'architecture': platform.machine()
                }
        except Exception as e:
            logger.error(f"Error detecting OS: {e}")
            return {
                'name': 'unknown',
                'version': 'unknown',
                'family': 'unknown',
                'architecture': 'unknown'
            }

    def _detect_linux(self) -> Dict[str, str]:
        """Detecta distribución Linux específica"""
        try:
            # Intentar leer /etc/os-release
            os_release = {}
            try:
                with open('/etc/os-release', 'r') as f:
                    for line in f:
                        if '=' in line:
                            key, value = line.strip().split('=', 1)
                            os_release[key] = value.strip('"')
            except FileNotFoundError:
                pass

            name = os_release.get('NAME', 'Linux')
            version = os_release.get('VERSION', platform.release())

            # Detectar familia
            family = 'linux'
            if 'ubuntu' in name.lower() or 'debian' in name.lower():
                family = 'debian'
            elif 'centos' in name.lower() or 'rhel' in name.lower() or 'fedora' in name.lower():
                family = 'redhat'
            elif 'arch' in name.lower():
                family = 'arch'
            elif 'alpine' in name.lower():
                family = 'alpine'

            return {
                'name': name,
                'version': version,
                'family': family,
                'architecture': platform.machine()
            }

        except Exception as e:
            logger.debug(f"Error detecting Linux details: {e}")
            return {
                'name': 'Linux',
                'version': platform.release(),
                'family': 'linux',
                'architecture': platform.machine()
            }

    def _detect_windows(self) -> Dict[str, str]:
        """Detecta versión de Windows"""
        try:
            version = platform.version()
            release = platform.release()

            return {
                'name': 'Windows',
                'version': f"{release} {version}",
                'family': 'windows',
                'architecture': platform.machine()
            }
        except Exception as e:
            logger.debug(f"Error detecting Windows details: {e}")
            return {
                'name': 'Windows',
                'version': 'unknown',
                'family': 'windows',
                'architecture': platform.machine()
            }

    def _detect_macos(self) -> Dict[str, str]:
        """Detecta versión de macOS"""
        try:
            version = platform.mac_ver()[0]

            return {
                'name': 'macOS',
                'version': version,
                'family': 'darwin',
                'architecture': platform.machine()
            }
        except Exception as e:
            logger.debug(f"Error detecting macOS details: {e}")
            return {
                'name': 'macOS',
                'version': 'unknown',
                'family': 'darwin',
                'architecture': platform.machine()
            }

    def _detect_firewall(self) -> Dict[str, str]:
        """Detecta tipo y estado del firewall"""
        os_family = self.os_info['family']

        if os_family in ['debian', 'redhat', 'linux', 'arch', 'alpine']:
            return self._detect_linux_firewall()
        elif os_family == 'windows':
            return self._detect_windows_firewall()
        elif os_family == 'darwin':
            return self._detect_macos_firewall()
        else:
            return {
                'type': 'unknown',
                'version': 'unknown',
                'status': 'unknown'
            }

    def _detect_linux_firewall(self) -> Dict[str, str]:
        """Detecta firewall en Linux (método simplificado)"""

        # Orden de prioridad: ufw -> firewalld -> iptables

        # 1. UFW (más común en Ubuntu/Debian)
        if shutil.which('ufw'):
            try:
                result = subprocess.run(['ufw', 'status'],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    status = 'active' if 'Status: active' in result.stdout else 'inactive'
                    return {'type': 'ufw', 'version': 'installed', 'status': status}
            except Exception:
                pass

        # 2. firewalld (común en CentOS/RHEL/Fedora)
        if shutil.which('firewall-cmd'):
            try:
                result = subprocess.run(['systemctl', 'is-active', 'firewalld'],
                                        capture_output=True, text=True, timeout=5)
                status = 'active' if result.returncode == 0 else 'inactive'
                return {'type': 'firewalld', 'version': 'installed', 'status': status}
            except Exception:
                pass

        # 3. iptables (fallback, casi siempre presente)
        if shutil.which('iptables'):
            try:
                result = subprocess.run(['iptables', '-L', '-n'],
                                        capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    # Heurística simple: si hay más que reglas por defecto, está "activo"
                    lines = result.stdout.strip().split('\n')
                    has_custom_rules = len(lines) > 8
                    status = 'active' if has_custom_rules else 'inactive'
                    return {'type': 'iptables', 'version': 'installed', 'status': status}
            except Exception:
                pass

        return {'type': 'unknown', 'version': 'unknown', 'status': 'unknown'}

    def _detect_windows_firewall(self) -> Dict[str, str]:
        """Detecta Windows Firewall"""
        try:
            result = subprocess.run([
                'netsh', 'advfirewall', 'show', 'allprofiles', 'state'
            ], capture_output=True, text=True, timeout=10)

            if result.returncode == 0:
                # Verificar si algún perfil está ON
                status = 'active' if 'State                                 ON' in result.stdout else 'inactive'
                return {'type': 'windows_firewall', 'version': 'builtin', 'status': status}
        except Exception:
            pass

        return {'type': 'windows_firewall', 'version': 'unknown', 'status': 'unknown'}

    def _detect_macos_firewall(self) -> Dict[str, str]:
        """Detecta macOS Firewall (pf)"""
        try:
            result = subprocess.run(['pfctl', '-s', 'info'],
                                    capture_output=True, text=True, timeout=5)

            if result.returncode == 0:
                status = 'active' if 'Status: Enabled' in result.stdout else 'inactive'
                return {'type': 'pf', 'version': 'builtin', 'status': status}
        except Exception:
            pass

        return {'type': 'pf', 'version': 'unknown', 'status': 'unknown'}

    def _generate_node_id(self) -> str:
        """Genera ID único y reproducible para el nodo"""
        try:
            # Combinar hostname + arquitectura para ID reproducible
            hostname = socket.gethostname()
            architecture = self.os_info['architecture']
            os_name = self.os_info['name']

            # Crear namespace único pero reproducible
            node_string = f"{hostname}-{os_name}-{architecture}"

            # Usar UUID5 para ID reproducible
            namespace = uuid.uuid5(uuid.NAMESPACE_DNS, "upgraded-happiness")
            node_id = str(uuid.uuid5(namespace, node_string))

            return node_id

        except Exception as e:
            logger.warning(f"Error generating reproducible node ID: {e}")
            # Fallback a UUID random
            return str(uuid.uuid4())

    def get_network_interfaces(self) -> List[str]:
        """Obtiene lista básica de interfaces de red"""
        try:
            if self.os_info['family'] in ['linux', 'debian', 'redhat', 'arch', 'alpine']:
                # Linux: usar ip command o ifconfig
                if shutil.which('ip'):
                    result = subprocess.run(['ip', 'link', 'show'],
                                            capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        interfaces = []
                        for line in result.stdout.split('\n'):
                            if ': ' in line and 'state UP' in line:
                                interface = line.split(':')[1].strip().split('@')[0]
                                if interface != 'lo':  # Skip loopback
                                    interfaces.append(interface)
                        return interfaces

            elif self.os_info['family'] == 'windows':
                # Windows: usar netsh
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'],
                                        capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    interfaces = []
                    for line in result.stdout.split('\n'):
                        if 'Connected' in line and 'Dedicated' in line:
                            # Extraer nombre de interface (formato específico)
                            parts = line.split()
                            if len(parts) >= 4:
                                interface = ' '.join(parts[3:])
                                interfaces.append(interface)
                    return interfaces

            elif self.os_info['family'] == 'darwin':
                # macOS: usar networksetup
                result = subprocess.run(['networksetup', '-listallhardwareports'],
                                        capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    interfaces = []
                    for line in result.stdout.split('\n'):
                        if line.startswith('Device: '):
                            device = line.replace('Device: ', '').strip()
                            if device != 'lo0':
                                interfaces.append(device)
                    return interfaces

        except Exception as e:
            logger.debug(f"Error detecting network interfaces: {e}")

        # Fallback: interfaces comunes
        return ['eth0', 'wlan0'] if self.os_info['family'] != 'windows' else ['Ethernet', 'Wi-Fi']

    def get_system_summary(self) -> Dict:
        """Retorna resumen completo del sistema"""
        return {
            'node_id': self.node_id,
            'hostname': socket.gethostname(),
            'os_name': self.os_info['name'],
            'os_version': self.os_info['version'],
            'os_family': self.os_info['family'],
            'architecture': self.os_info['architecture'],
            'firewall_type': self.firewall_info['type'],
            'firewall_version': self.firewall_info['version'],
            'firewall_status': self.firewall_info['status'],
            'interfaces': self.get_network_interfaces(),
            'agent_version': '1.0.0',
            'detection_timestamp': int(__import__('time').time())
        }

    def print_summary(self):
        """Imprime resumen del sistema detectado"""
        summary = self.get_system_summary()

        print("🔍 System Detection Summary")
        print("=" * 40)
        print(f"🆔 Node ID: {summary['node_id']}")
        print(f"🖥️  Hostname: {summary['hostname']}")
        print(f"🖥️  OS: {summary['os_name']} {summary['os_version']}")
        print(f"📁 Family: {summary['os_family']}")
        print(f"🏗️  Architecture: {summary['architecture']}")
        print(f"🔥 Firewall: {summary['firewall_type']} ({summary['firewall_status']})")
        print(f"🌐 Interfaces: {', '.join(summary['interfaces'])}")
        print(f"📦 Agent Version: {summary['agent_version']}")


def main():
    """Función de testing"""
    import json

    # Configurar logging para testing
    logging.basicConfig(level=logging.INFO,
                        format='%(levelname)s: %(message)s')

    print("🚀 Testing Simple System Detection")
    print("=" * 50)

    # Crear detector
    detector = SimpleSystemDetector()

    # Mostrar resumen
    detector.print_summary()

    # Mostrar JSON completo
    print("\n📄 JSON Output:")
    summary = detector.get_system_summary()
    print(json.dumps(summary, indent=2))

    # Test de reproducibilidad del node_id
    print(f"\n🔄 Node ID consistency test:")
    detector2 = SimpleSystemDetector()
    print(f"First:  {detector.node_id}")
    print(f"Second: {detector2.node_id}")
    print(f"Match: {'✅' if detector.node_id == detector2.node_id else '❌'}")


if __name__ == "__main__":
    main()