"""
ShieldNet SOAR Firewall Orchestration Engine.

Demonstrates the deliberate architectural separation between:
1. The Notary (SIERL Blockchain Ledger): Validates policy threshold, immutably records decision.
2. The Executioner (Firewall Orchestrator): Reads the authorized ledger record and executes firewall actions.

Blockchain never directly touches network interfaces; orchestration translates ledger commitments
into standard firewall/SDN enforcement (iptables, nftables, BGP Blackhole, OpenFlow drop).
"""

import time
import datetime
from typing import Dict, Any, Optional


class FirewallOrchestrator:
    """Simulated production firewall / SOAR actuator."""

    def __init__(self):
        self.execution_log = []

    def execute_action(
        self,
        incident_id: str,
        action_type: str,
        target_ip: str,
        port: Optional[int] = None,
        approver_role: str = "Admin",
        transaction_hash: str = ""
    ) -> Dict[str, Any]:
        """
        Translates an authorized ledger commitment into firewall commands
        and records execution telemetry.
        """
        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        # Determine specific firewall rule syntax
        if "BLOCK" in action_type.upper() or "DROP" in action_type.upper() or "ISOLATE" in action_type.upper():
            cmd_iptables = f"iptables -I INPUT 1 -s {target_ip} -j DROP -m comment --comment 'ShieldNet SIERL [{incident_id}]'"
            cmd_nftables = f"nft add rule ip filter input ip saddr {target_ip} counter drop"
            effect = f"Immediate ingress traffic drop for {target_ip}"
        elif "RATE_LIMIT" in action_type.upper() or "THROTTLE" in action_type.upper():
            cmd_iptables = f"iptables -A INPUT -p tcp -s {target_ip} -m limit --limit 25/minute --limit-burst 100 -j ACCEPT"
            cmd_nftables = f"nft add rule ip filter input ip saddr {target_ip} limit rate 25/minute accept"
            effect = f"Adaptive rate-limit applied to {target_ip} (25 pkts/min)"
        elif "RESET" in action_type.upper():
            cmd_iptables = f"iptables -A INPUT -p tcp -s {target_ip} --dport {port or 80} -j REJECT --reject-with tcp-reset"
            cmd_nftables = f"nft add rule ip filter input ip saddr {target_ip} tcp dport {port or 80} reject with tcp reset"
            effect = f"TCP Reset sent to active connection from {target_ip}:{port or 80}"
        else:
            cmd_iptables = f"iptables -I FORWARD -s {target_ip} -j LOG --log-prefix 'SHIELDNET_ALERT: '"
            cmd_nftables = f"nft add rule ip filter forward ip saddr {target_ip} log prefix 'SHIELDNET_ALERT: '"
            effect = f"Enhanced forensic packet logging enabled for {target_ip}"

        execution_record = {
            "execution_id": f"exec_{int(time.time() * 1000)}",
            "incident_id": incident_id,
            "action_type": action_type,
            "target_ip": target_ip,
            "port": port,
            "authorized_by": approver_role,
            "ledger_tx_hash": transaction_hash,
            "executed_at": now,
            "status": "ENFORCED",
            "effect": effect,
            "generated_rules": {
                "iptables": cmd_iptables,
                "nftables": cmd_nftables,
                "sdn_openflow": f"ovs-ofctl add-flow br0 priority=40000,dl_type=0x0800,nw_src={target_ip},actions=drop"
            }
        }
        
        self.execution_log.append(execution_record)
        return execution_record

    def get_recent_executions(self, limit: int = 20) -> list:
        return self.execution_log[-limit:]


_ORCHESTRATOR_INSTANCE = None

def get_firewall_orchestrator() -> FirewallOrchestrator:
    global _ORCHESTRATOR_INSTANCE
    if _ORCHESTRATOR_INSTANCE is None:
        _ORCHESTRATOR_INSTANCE = FirewallOrchestrator()
    return _ORCHESTRATOR_INSTANCE
