#!/usr/bin/env python3
"""Blockchain Intelligence Platform CLI"""
import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from blockchain_intelligence_platform.intelligence import (
    BlockchainIntelligence, ThreatIntelligenceFeed
)

async def analyze_address(address: str, chain: str = "ethereum"):
    """Analyze single address"""
    intel = BlockchainIntelligence()
    
    print(f"Analyzing {address} on {chain}...")
    profile = await intel.analyze_wallet(address, chain)
    
    print("\n" + "=" * 70)
    print(f"Wallet Profile: {address}")
    print("=" * 70)
    print(f"Risk Score: {profile.risk_score:.1f}/100")
    print(f"Risk Level: {intel._score_to_level(profile.risk_score)}")
    print(f"Tags: {', '.join(profile.tags) if profile.tags else 'None'}")
    print("=" * 70)

async def demo_monitoring():
    """Demo wallet monitoring"""
    print("=" * 70)
    print("Blockchain Intelligence Platform - Demo")
    print("=" * 70)
    
    intel = BlockchainIntelligence()
    
    # Demo addresses (sample)
    addresses = [
        "0x742d35Cc6634C0532925a3b8D4e6D3b6e8d3e8A0",
        "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
        "0xA0b86a33E6441c3be0c7e0d4E3E6D7b8E5F4C3A2"
    ]
    
    def on_profile(profile):
        risk_emoji = "🚨" if profile.risk_score > 50 else "⚠️" if profile.risk_score > 20 else "✅"
        print(f"{risk_emoji} {profile.address[:30]}... | Risk: {profile.risk_score:.1f} | Tags: {profile.tags}")
    
    await intel.monitor_addresses(addresses, callback=on_profile)
    
    print("\n" + "=" * 70)
    print("Generating intelligence report for first address...")
    report = intel.generate_intelligence_report(addresses[0])
    print(json.dumps(report, indent=2))

def threat_feed_demo():
    """Demo threat intelligence feed"""
    feed = ThreatIntelligenceFeed()
    
    # Add sample threats
    feed.add_threat(
        "0xBadAddress1234567890abcdef",
        "phishing",
        "Known phishing contract"
    )
    feed.add_threat(
        "0xExploit5678901234567890abcd",
        "exploit",
        "Flash loan attack contract"
    )
    
    print("=" * 70)
    print("Threat Intelligence Feed")
    print("=" * 70)
    print(f"Known Threats: {len(feed.known_threats)}")
    print(f"Recent Attacks: {len(feed.recent_attacks)}")
    
    # Check addresses
    test_addrs = [
        "0xBadAddress1234567890abcdef",
        "0xSafeAddress1234567890abcd"
    ]
    
    for addr in test_addrs:
        result = feed.check_address(addr)
        if result:
            print(f"🚨 {addr[:30]}... FLAGGED: {result['reason']}")
        else:
            print(f"✅ {addr[:30]}... Clean")

def main():
    parser = argparse.ArgumentParser(description="Blockchain Intelligence Platform")
    parser.add_argument("--analyze", help="Address to analyze")
    parser.add_argument("--chain", default="ethereum", help="Blockchain network")
    parser.add_argument("--demo", action="store_true", help="Run demo")
    
    args = parser.parse_args()
    
    if args.analyze:
        asyncio.run(analyze_address(args.analyze, args.chain))
    else:
        # Run all demos
        asyncio.run(demo_monitoring())
        print("\n")
        threat_feed_demo()

if __name__ == "__main__":
    main()
