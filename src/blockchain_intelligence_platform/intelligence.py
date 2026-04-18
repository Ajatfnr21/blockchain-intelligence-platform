"""
Blockchain Intelligence Platform - Multi-chain monitoring and threat detection
"""
import asyncio
import aiohttp
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import json

@dataclass
class ThreatIndicator:
    type: str
    description: str
    severity: str
    addresses: List[str]
    confidence: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class WalletProfile:
    address: str
    risk_score: float
    tags: List[str]
    associated_addresses: List[str]
    transaction_count: int
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None

class BlockchainIntelligence:
    """Main intelligence platform"""
    
    THREAT_PATTERNS = {
        "mixer_usage": ["tornado.cash", "0x12...", "0x34..."],
        "exchange": ["binance", "coinbase", "kraken"],
        "scam": ["phishing", "fake_token"],
        "hack": ["exploit", "drainer"]
    }
    
    def __init__(self, rpc_endpoints: Optional[Dict[str, str]] = None):
        self.rpc_endpoints = rpc_endpoints or {
            "ethereum": "https://eth.llamarpc.com",
            "polygon": "https://polygon.llamarpc.com",
            "arbitrum": "https://arb1.arbitrum.io/rpc"
        }
        self.threat_db: List[ThreatIndicator] = []
        self.wallet_db: Dict[str, WalletProfile] = {}
    
    async def analyze_wallet(self, address: str, chain: str = "ethereum") -> WalletProfile:
        """Analyze wallet for risk indicators"""
        tags = []
        risk_score = 0.0
        
        # Check against threat patterns
        for threat_type, patterns in self.THREAT_PATTERNS.items():
            if any(pattern.lower() in address.lower() for pattern in patterns):
                tags.append(threat_type)
                risk_score += 30 if threat_type in ["hack", "scam"] else 10
        
        # Calculate risk based on tags
        risk_score = min(risk_score, 100)
        
        profile = WalletProfile(
            address=address,
            risk_score=risk_score,
            tags=tags,
            associated_addresses=[],
            transaction_count=0
        )
        
        self.wallet_db[address] = profile
        return profile
    
    def detect_threats(self, transaction: Dict) -> List[ThreatIndicator]:
        """Detect threats in transaction"""
        threats = []
        
        # High value transfer
        value = float(transaction.get("value", 0)) / 1e18
        if value > 1000:
            threats.append(ThreatIndicator(
                type="high_value_transfer",
                description=f"Large transfer: {value:.2f} ETH",
                severity="medium",
                addresses=[transaction.get("from", ""), transaction.get("to", "")],
                confidence=0.9
            ))
        
        # Check for mixer interaction
        to_addr = transaction.get("to", "").lower()
        if any(mixer in to_addr for mixer in ["tornado"]):
            threats.append(ThreatIndicator(
                type="mixer_interaction",
                description="Interaction with privacy mixer detected",
                severity="high",
                addresses=[transaction.get("from", "")],
                confidence=0.85
            ))
        
        # Check for suspicious patterns
        if transaction.get("gasPrice", 0) > 500e9:  # 500 Gwei
            threats.append(ThreatIndicator(
                type="front_running",
                description="Extremely high gas price - possible front-running",
                severity="medium",
                addresses=[transaction.get("from", "")],
                confidence=0.7
            ))
        
        self.threat_db.extend(threats)
        return threats
    
    def generate_intelligence_report(self, address: str) -> Dict:
        """Generate comprehensive intelligence report"""
        profile = self.wallet_db.get(address)
        
        if not profile:
            return {"error": "Address not analyzed"}
        
        # Find related threats
        related_threats = [
            t for t in self.threat_db
            if address in t.addresses
        ]
        
        return {
            "address": address,
            "risk_score": profile.risk_score,
            "risk_level": self._score_to_level(profile.risk_score),
            "tags": profile.tags,
            "transaction_count": profile.transaction_count,
            "threats_detected": len(related_threats),
            "threat_indicators": [
                {
                    "type": t.type,
                    "description": t.description,
                    "severity": t.severity,
                    "confidence": t.confidence
                }
                for t in related_threats
            ]
        }
    
    def _score_to_level(self, score: float) -> str:
        if score >= 70:
            return "HIGH_RISK"
        elif score >= 40:
            return "MEDIUM_RISK"
        elif score >= 10:
            return "LOW_RISK"
        return "SAFE"
    
    async def monitor_addresses(self, addresses: List[str], callback=None):
        """Monitor addresses for new activity"""
        print(f"Monitoring {len(addresses)} addresses...")
        
        for addr in addresses:
            profile = await self.analyze_wallet(addr)
            
            if callback:
                callback(profile)
            else:
                print(f"Profiled {addr[:20]}... Risk: {profile.risk_score:.1f}")

class ThreatIntelligenceFeed:
    """Real-time threat intelligence feed"""
    
    def __init__(self):
        self.known_threats: Set[str] = set()
        self.recent_attacks: List[Dict] = []
    
    def add_threat(self, address: str, threat_type: str, description: str):
        """Add new threat to database"""
        self.known_threats.add(address.lower())
        self.recent_attacks.append({
            "address": address,
            "type": threat_type,
            "description": description,
            "timestamp": datetime.now().isoformat()
        })
    
    def check_address(self, address: str) -> Optional[Dict]:
        """Check if address is known threat"""
        if address.lower() in self.known_threats:
            return {
                "flagged": True,
                "address": address,
                "reason": "Known malicious address"
            }
        return None
