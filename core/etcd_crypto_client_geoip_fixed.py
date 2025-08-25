#!/usr/bin/env python3
"""
core/etcd_crypto_client_geoip_fixed.py
🔍 Cliente ETCD REAL - GEOIP_ENRICHER
================================================================================
BASADO EN LA PLANTILLA DEL DASHBOARD - SIN FALLBACKS, SOLO ETCD PURO
"""

import asyncio
import json
import logging
import os
import sys
import socket
import etcd3
from datetime import datetime
from typing import Dict, Optional, Union
from dataclasses import dataclass

# 🚨 HARD REQUIREMENT: ETCD MUST BE AVAILABLE
# NO FALLBACKS, NO MOCKS, NO FAKE BEHAVIOR
ETCD_REQUIRED = True

@dataclass
class GeoipEnricherETCDConfig:
    """Configuración ETCD extraída desde el config JSON del componente"""
    etcd_host: str
    etcd_port: int
    cluster_name: str
    node_id: str

class ETCDCryptoClientGeoIP:
    """🔍 Cliente ETCD REAL para GEOIP_ENRICHER"""

    def __init__(self, geoip_config_path: str):
        """
        Inicializar cliente ETCD REAL

        Args:
            geoip_config_path: Ruta al config JSON del componente
        """
        self.geoip_config_path = geoip_config_path
        self.component_config = None
        self.etcd_config = None
        self.crypto_token = None

        # Setup logging
        self.logger = logging.getLogger(f"geoip_enricher_etcd_client")
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - GEOIP_ENRICHER_ETCD - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)

    def _load_component_config(self):
        """Cargar configuración del componente"""
        try:
            with open(self.geoip_config_path, 'r') as f:
                self.component_config = json.load(f)

            self.logger.info(f"✅ {'geoip_enricher'.title()} config loaded successfully")

        except json.JSONDecodeError as e:
            raise ValueError(f"❌ Invalid JSON in {'geoip_enricher'} config: {e}")
        except Exception as e:
            raise RuntimeError(f"❌ Failed to load {'geoip_enricher'} config: {e}")

    
        
        
            
            
        
        
            
                
            
            
            
        
            
        
            

    def _extract_etcd_config(self):
        """Extraer configuración ETCD del config del componente"""
        if not self.component_config:
            raise ValueError("❌ Component config must be loaded first")

        if 'etcd_crypto' not in self.component_config:
            raise KeyError(
                f"❌ REQUIRED section 'etcd_crypto' not found in {'geoip_enricher'} config.\n"
                f"   Add 'etcd_crypto' section to {self.geoip_config_path}"
            )

        etcd_section = self.component_config['etcd_crypto']

        # OBLIGATORIO: campos requeridos
        required_fields = ['etcd_host', 'etcd_port', 'cluster_name', 'node_id']
        missing_fields = [field for field in required_fields if field not in etcd_section]

        if missing_fields:
            raise KeyError(
                f"❌ REQUIRED fields missing in etcd_crypto section: {missing_fields}\n"
                f"   Add these fields to {self.geoip_config_path}"
            )

        self.etcd_config = GeoipEnricherETCDConfig(
            etcd_host=etcd_section['etcd_host'],
            etcd_port=etcd_section['etcd_port'],
            cluster_name=etcd_section['cluster_name'],
            node_id=etcd_section['node_id']
        )

        self.logger.info(f"✅ ETCD config extracted: {self.etcd_config.etcd_host}:{self.etcd_config.etcd_port}")

    async def _register_configs_in_etcd(self):
        """🎯 Registrar configuración(es) en ETCD - PATRÓN DASHBOARD"""
        try:
            self.logger.info(f"📊 Registering geoip_enricher config in ETCD...")

            # Crear cliente ETCD REAL
            etcd_client = etcd3.client(
                host=self.etcd_config.etcd_host,
                port=self.etcd_config.etcd_port
            )

            # Registrar config principal del componente
            component_config_key = "/upgraded-happiness/v31/components/geoip/config"
            component_config_data = {
                "config_type": "geoip_config",
                "node_id": self.etcd_config.node_id,
                "component_type": "geoip_enricher",
                "config_data": self.component_config,
                "timestamp": datetime.now().isoformat(),
                "config_version": self.component_config.get('_config_metadata', {}).get('config_version', '3.1.0')
            }

            # PUT a ETCD
            etcd_client.put(component_config_key, json.dumps(component_config_data, indent=2))
            self.logger.info(f"✅ Geoip_Enricher config registered at: {component_config_key}")

            
            
                
                
                    
                    
                    
                    
                    
                    
                
                
                
                
                

            self.logger.info(f"📊 Geoip_Enricher config registration completed successfully")

        except Exception as e:
            self.logger.error(f"❌ Config registration failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS
            raise RuntimeError(f"ETCD config registration failed for {'geoip_enricher'}: {e}")

    async def initialize_crypto(self) -> bool:
        """
        Inicializar cliente ETCD y registrar configuraciones
        🚨 HARD FAIL si ETCD no está disponible
        """
        try:
            self.logger.info(f"🚀 Initializing geoip_enricher ETCD crypto...")

            # 1. Cargar configuraciones
            self._load_component_config()

            # 2. Extraer config ETCD
            self._extract_etcd_config()

            # 3. Registrar en ETCD
            await self._register_configs_in_etcd()

            # 4. Generar token crypto (simplificado por ahora)
            self.crypto_token = {
                'key': f"{'geoip_enricher'}_key_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                'version': 'v3.1.0',
                'timestamp': datetime.now().isoformat()
            }

            self.logger.info(f"✅ Geoip_Enricher crypto initialization successful!")
            self.logger.info(f"🔑 Token version: {self.crypto_token['version']}")

            return True

        except Exception as e:
            self.logger.error(f"❌ Crypto initialization failed: {e}")
            # 🚨 HARD FAIL - NO FALLBACKS, NO MOCKS
            raise RuntimeError(f"ETCD initialization failed for geoip_enricher: {e}")

    def get_pipeline_key(self) -> Optional[str]:
        """Obtener UPGRADED_HAPPINESS_PIPELINE_KEY para geoip_enricher"""
        if not self.crypto_token:
            return None
        return self.crypto_token['key']

    def is_crypto_ready(self) -> bool:
        """Verificar si crypto está listo"""
        return self.crypto_token is not None

    def get_status(self) -> Dict:
        """Obtener status del cliente ETCD"""
        return {
            'component': 'geoip_enricher',
            'crypto_ready': self.is_crypto_ready(),
            'etcd_config': {
                'host': self.etcd_config.etcd_host if self.etcd_config else None,
                'port': self.etcd_config.etcd_port if self.etcd_config else None,
                'cluster': self.etcd_config.cluster_name if self.etcd_config else None,
                'node_id': self.etcd_config.node_id if self.etcd_config else None
            } if self.etcd_config else None,
            'token_version': self.crypto_token['version'] if self.crypto_token else None
        }

# 🎯 FUNCIONES PÚBLICAS PARA COMPATIBILIDAD
async def setup_geoip_crypto(geoip_config_path: str) -> bool:
    """
    Setup crypto para geoip_enricher

    Args:
        geoip_config_path: Ruta al config JSON del componente

    Returns:
        True si exitoso

    Raises:
        RuntimeError si ETCD no está disponible
    """
    global _etcd_client
    _etcd_client = ETCDCryptoClientGeoIP(geoip_config_path)

    success = await _etcd_client.initialize_crypto()
    if not success:
        raise RuntimeError(f"Failed to initialize {'geoip_enricher'} ETCD crypto")

    return True

def get_geoip_pipeline_key() -> Optional[str]:
    """Obtener pipeline key para geoip_enricher"""
    global _etcd_client
    if not _etcd_client:
        return None
    return _etcd_client.get_pipeline_key()

def get_geoip_crypto_status() -> Dict:
    """Obtener status crypto para geoip_enricher"""
    global _etcd_client
    if not _etcd_client:
        return {'status': 'not_initialized'}
    return _etcd_client.get_status()

# Cliente global
_etcd_client: Optional[ETCDCryptoClientGeoIP] = None

if __name__ == "__main__":
    # Test básico
    import asyncio

    async def test_geoip_etcd():
        """Test básico del cliente ETCD"""
        print(f"🧪 Testing geoip_enricher ETCD client...")

        # Esto requiere que ETCD esté corriendo y config válido
        # python core/etcd_crypto_client_geoip_fixed.py

        print("🚨 Para test real, usa un config válido y ETCD corriendo")

    if len(sys.argv) > 1:
        print(f"🔧 Para integrar: from core.etcd_crypto_client_geoip_fixed import setup_geoip_crypto, get_geoip_pipeline_key")
    else:
        asyncio.run(test_geoip_etcd())
