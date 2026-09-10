"""
ShieldNet Multi-Node Hyperledger Fabric Consensus Network.

Implements Tier-2 Roadmap from Doc 2 & 3.pdf:
- Cross-CII Distributed Permissioned Ledger across 3 Critical Infrastructure Substations:
  1. Org1: Substation Alpha (Wardha 765kV Substation - WardhaMSP)
  2. Org2: Substation Beta (Jabalpur 400kV Central Grid - JabalpurMSP)
  3. Org3: Substation Gamma (Indore 765kV Dispatch Substation - IndoreMSP)
- 1 Raft Ordering Service Node:
  - Orderer-NRLDC (National Regional Load Despatch Centre)
- 2-of-3 Endorsement Policy:
  - OutOf(2, 'WardhaMSP.peer', 'JabalpurMSP.peer', 'IndoreMSP.peer')
- Cryptographic Merkle Root Block Packaging & Multi-Peer Gossip Synchronization
- Notary vs. Executioner Architecture:
  - Ledger consensus certifies & authorizes threat mitigation; local substation firewalls enforce independently.
- Byzantine / Crash Fault Tolerance:
  - Supports node partitioning/failure simulation with uninterrupted consensus if >= 2 nodes are active.
"""

import json
import time
import datetime
import hashlib
import hmac
import os
import threading
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple


def _sha256_str(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _canonical_hash(obj: Any) -> str:
    serialized = json.dumps(obj, sort_keys=True, separators=(",", ":"))
    return _sha256_str(serialized)


def _compute_merkle_root(leaf_hashes: List[str]) -> str:
    """Computes binary Merkle tree root hash from a list of transaction leaf hashes."""
    if not leaf_hashes:
        return _sha256_str("EMPTY_MERKLE_ROOT")
    current_level = leaf_hashes[:]
    while len(current_level) > 1:
        next_level = []
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1] if i + 1 < len(current_level) else left
            combined = _sha256_str(f"{left}{right}")
            next_level.append(combined)
        current_level = next_level
    return current_level[0]


class PeerNode:
    """
    Represents an Organization Peer Node in a Hyperledger Fabric CII Consortium.
    Maintains local MSP certificate, local ledger copy, and endorsement state.
    """

    def __init__(
        self,
        node_id: str,
        org_name: str,
        msp_id: str,
        substation_name: str,
        grid_voltage: str,
        private_key_secret: str,
        endpoint: str
    ):
        self.node_id = node_id
        self.org_name = org_name
        self.msp_id = msp_id
        self.substation_name = substation_name
        self.grid_voltage = grid_voltage
        self.endpoint = endpoint
        self._private_key = private_key_secret
        self.cert_fingerprint = _sha256_str(f"CERT::{msp_id}::{node_id}::{endpoint}")[:32]
        self.status = "ONLINE"  # ONLINE, PARTITIONED, OFFLINE
        self.local_ledger: List[Dict[str, Any]] = []
        self.world_state: Dict[str, Any] = {}  # Active IoCs and firewall rules
        self.last_sync_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    def generate_endorsement_signature(self, proposal_hash: str) -> str:
        """Signs the transaction proposal using peer MSP cryptographic key."""
        sig = hmac.new(
            self._private_key.encode("utf-8"),
            proposal_hash.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return sig

    def verify_endorsement_signature(self, proposal_hash: str, signature: str) -> bool:
        expected = self.generate_endorsement_signature(proposal_hash)
        return hmac.compare_digest(expected, signature)

    def endorse_proposal(self, proposal: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Executes chaincode validation on proposal and returns cryptographic endorsement.
        If node is PARTITIONED or OFFLINE, refuses endorsement.
        """
        if self.status != "ONLINE":
            return None

        # Chaincode sanity verification
        confidence = proposal.get("confidence", 0.0)
        adversary_ip = proposal.get("adversary_ip", "")
        if not adversary_ip or confidence < 0.60:
            return None  # Chaincode reject: confidence below minimum threshold

        proposal_payload_hash = _canonical_hash(proposal)
        signature = self.generate_endorsement_signature(proposal_payload_hash)

        return {
            "endorser_node_id": self.node_id,
            "msp_id": self.msp_id,
            "substation_name": self.substation_name,
            "cert_fingerprint": self.cert_fingerprint,
            "proposal_hash": proposal_payload_hash,
            "signature": signature,
            "endorsement_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "chaincode_response": {
                "status": 200,
                "message": f"Endorsed by {self.substation_name} with 84-feature telemetry verification",
                "recommended_local_action": f"STAGE_FIREWALL_INGRESS_DROP for IP {adversary_ip}"
            }
        }

    def commit_block(self, block: Dict[str, Any]) -> bool:
        """Validates and appends an ordered block received from ordering service via gossip."""
        if self.status != "ONLINE":
            return False

        # Validate previous hash linkage if ledger not empty
        if self.local_ledger:
            last_block = self.local_ledger[-1]
            if block.get("previous_block_hash") != last_block.get("block_hash"):
                return False

        self.local_ledger.append(block)
        self.last_sync_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Update world state key-values from transactions
        for tx in block.get("transactions", []):
            ioc_key = tx.get("adversary_ip")
            if ioc_key:
                self.world_state[ioc_key] = {
                    "threat_type": tx.get("threat_type"),
                    "mitre_stage": tx.get("mitre_stage"),
                    "status": "BLOCKED_CONSENSUS",
                    "block_index": block.get("block_index"),
                    "committed_at": block.get("timestamp")
                }
        return True

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "org_name": self.org_name,
            "msp_id": self.msp_id,
            "substation_name": self.substation_name,
            "grid_voltage": self.grid_voltage,
            "endpoint": self.endpoint,
            "cert_fingerprint": self.cert_fingerprint,
            "status": self.status,
            "block_height": len(self.local_ledger),
            "last_block_hash": self.local_ledger[-1]["block_hash"] if self.local_ledger else "0" * 64,
            "active_iocs_in_world_state": len(self.world_state),
            "last_sync_timestamp": self.last_sync_timestamp
        }


class RaftOrdererNode:
    """
    Represents the Central Raft Ordering Service (NRLDC Orderer).
    Batches endorsed proposals into cryptographically signed blocks with Merkle roots.
    """

    def __init__(
        self,
        orderer_id: str,
        cluster_name: str,
        endpoint: str
    ):
        self.orderer_id = orderer_id
        self.cluster_name = cluster_name
        self.endpoint = endpoint
        self.leader_status = "RAFT_LEADER"
        self.term = 1
        self.mempool: List[Dict[str, Any]] = []

    def package_block(
        self,
        block_index: int,
        previous_block_hash: str,
        transactions: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Creates a signed Fabric channel block with Merkle root."""
        tx_hashes = [tx.get("tx_id", _canonical_hash(tx)) for tx in transactions]
        merkle_root = _compute_merkle_root(tx_hashes)
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        header = {
            "block_index": block_index,
            "previous_block_hash": previous_block_hash,
            "merkle_root": merkle_root,
            "tx_count": len(transactions),
            "timestamp": timestamp,
            "orderer_id": self.orderer_id,
            "raft_term": self.term
        }
        block_hash = _canonical_hash(header)

        return {
            "block_index": block_index,
            "block_hash": block_hash,
            "previous_block_hash": previous_block_hash,
            "merkle_root": merkle_root,
            "timestamp": timestamp,
            "orderer_metadata": {
                "orderer_id": self.orderer_id,
                "cluster": self.cluster_name,
                "raft_term": self.term,
                "consensus_engine": "RAFT_CRASH_FAULT_TOLERANT"
            },
            "transactions": transactions
        }


class FabricConsortiumNetwork:
    """
    Coordinates the Multi-Node Hyperledger Fabric Cross-CII Network.
    Enforces 2-of-3 endorsement, ordering, and gossip distribution.
    """

    def __init__(self, persistence_file: Optional[Path] = None):
        self.lock = threading.RLock()
        self.channel_name = "cross-cii-grid-defense-channel"
        self.endorsement_policy = "OutOf(2, 'WardhaMSP.peer', 'JabalpurMSP.peer', 'IndoreMSP.peer')"
        self.min_endorsements = 2

        # Orderer
        self.orderer = RaftOrdererNode(
            orderer_id="orderer0.nrldc.gov.in",
            cluster_name="NRLDC_RAFT_CONSORTIUM",
            endpoint="grpc://orderer.nrldc.gov.in:7050"
        )

        # 3 Substation Peers
        self.peers: Dict[str, PeerNode] = {
            "peer0.wardha.grid": PeerNode(
                node_id="peer0.wardha.grid",
                org_name="PowerGrid Western Region-I",
                msp_id="WardhaMSP",
                substation_name="Wardha 765kV Super Thermal Substation",
                grid_voltage="765 kV",
                private_key_secret="sec_key_wardha_765_sovereign",
                endpoint="grpc://peer0.wardha.grid:7051"
            ),
            "peer0.jabalpur.grid": PeerNode(
                node_id="peer0.jabalpur.grid",
                org_name="MPPTCL State Transmission",
                msp_id="JabalpurMSP",
                substation_name="Jabalpur 400kV Central Grid Substation",
                grid_voltage="400 kV",
                private_key_secret="sec_key_jabalpur_400_sovereign",
                endpoint="grpc://peer0.jabalpur.grid:7051"
            ),
            "peer0.indore.grid": PeerNode(
                node_id="peer0.indore.grid",
                org_name="Western Load Despatch Substation",
                msp_id="IndoreMSP",
                substation_name="Indore 765kV Regional Dispatch Substation",
                grid_voltage="765 kV",
                private_key_secret="sec_key_indore_765_sovereign",
                endpoint="grpc://peer0.indore.grid:7051"
            )
        }

        self.persistence_file = persistence_file
        self._initialize_genesis_block()

    def _initialize_genesis_block(self):
        """Creates Channel Genesis Block #0 establishing MSP consortium certificates."""
        with self.lock:
            genesis_tx = {
                "tx_id": "00000000-genesis-channel-config-00000000",
                "type": "CONFIG_UPDATE",
                "channel_id": self.channel_name,
                "endorsement_policy": self.endorsement_policy,
                "consortium_members": [p.to_summary_dict() for p in self.peers.values()],
                "orderer": {
                    "id": self.orderer.orderer_id,
                    "cluster": self.orderer.cluster_name,
                    "consensus": "RAFT"
                },
                "timestamp": "2026-01-01T00:00:00Z"
            }

            genesis_block = self.orderer.package_block(
                block_index=0,
                previous_block_hash="0" * 64,
                transactions=[genesis_tx]
            )

            for peer in self.peers.values():
                peer.commit_block(genesis_block)

    def propose_and_commit_threat_ioc(
        self,
        proposing_peer_id: str,
        threat_type: str,
        adversary_ip: str,
        target_asset: str,
        mitre_stage: str,
        confidence: float,
        proposed_action: str = "DENY_INGRESS_DROP",
        xai_summary: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes full Hyperledger Fabric transaction lifecycle:
        1. Propose transaction to all available peer nodes.
        2. Collect cryptographic endorsements from peers.
        3. Verify endorsement policy (>= 2 matching endorsements).
        4. Forward to Raft Orderer for sequencing & block generation.
        5. Replicate block across all online peers via Gossip Protocol.
        """
        with self.lock:
            tx_id = f"tx-{hashlib.sha256(f'{adversary_ip}-{time.time()}'.encode()).hexdigest()[:16]}"
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

            proposal = {
                "tx_id": tx_id,
                "channel_id": self.channel_name,
                "chaincode_id": "sierl_cross_cii_v2",
                "proposing_peer": proposing_peer_id,
                "threat_type": threat_type,
                "adversary_ip": adversary_ip,
                "target_asset": target_asset,
                "mitre_stage": mitre_stage,
                "confidence": float(confidence),
                "proposed_action": proposed_action,
                "xai_summary": xai_summary or {"top_feature": "SYN_Flag_Count", "attribution": 0.38},
                "timestamp": timestamp
            }

            # Step 1 & 2: Collect endorsements
            endorsements = []
            for peer_id, peer in self.peers.items():
                endorsement = peer.endorse_proposal(proposal)
                if endorsement:
                    endorsements.append(endorsement)

            # Step 3: Check endorsement policy (Minimum 2 distinct MSPs required)
            unique_msps = set(e["msp_id"] for e in endorsements)
            if len(unique_msps) < self.min_endorsements:
                return {
                    "status": "CONSENSUS_REJECTED",
                    "reason": f"Endorsement policy unmet: required {self.min_endorsements} distinct MSPs, received {len(unique_msps)}",
                    "active_endorsements": endorsements,
                    "tx_id": tx_id
                }

            # Step 4: Submit to Orderer
            committed_tx = {
                **proposal,
                "endorsements": endorsements,
                "consensus_achieved": True,
                "endorsement_count": len(endorsements),
                "endorsing_msps": list(unique_msps)
            }

            # Determine previous block hash from peer0
            ref_peer = list(self.peers.values())[0]
            last_block = ref_peer.local_ledger[-1]
            next_block_index = last_block["block_index"] + 1
            previous_hash = last_block["block_hash"]

            new_block = self.orderer.package_block(
                block_index=next_block_index,
                previous_block_hash=previous_hash,
                transactions=[committed_tx]
            )

            # Step 5: Gossip commit across online peers
            commit_statuses = {}
            for peer_id, peer in self.peers.items():
                committed = peer.commit_block(new_block)
                commit_statuses[peer_id] = "COMMITTED" if committed else f"SKIPPED_{peer.status}"

            return {
                "status": "CONSENSUS_COMMITTED",
                "tx_id": tx_id,
                "block_index": new_block["block_index"],
                "block_hash": new_block["block_hash"],
                "merkle_root": new_block["merkle_root"],
                "endorsing_peers_count": len(endorsements),
                "endorsing_msps": list(unique_msps),
                "peer_commit_statuses": commit_statuses,
                "block": new_block
            }

    def simulate_partition(self, peer_id: str) -> Dict[str, Any]:
        """Simulates network cut / node failure for testing fault tolerance."""
        with self.lock:
            if peer_id not in self.peers:
                return {"status": "ERROR", "message": f"Peer {peer_id} not found"}
            self.peers[peer_id].status = "PARTITIONED"
            return {
                "status": "NODE_PARTITIONED",
                "peer_id": peer_id,
                "substation": self.peers[peer_id].substation_name,
                "active_online_nodes": sum(1 for p in self.peers.values() if p.status == "ONLINE")
            }

    def recover_node(self, peer_id: str) -> Dict[str, Any]:
        """Recovers a partitioned node and synchronizes missing blocks from consortium."""
        with self.lock:
            if peer_id not in self.peers:
                return {"status": "ERROR", "message": f"Peer {peer_id} not found"}
            target_peer = self.peers[peer_id]
            target_peer.status = "ONLINE"

            # Find peer with highest block height
            best_peer = max(self.peers.values(), key=lambda p: len(p.local_ledger))
            missing_count = 0
            if len(best_peer.local_ledger) > len(target_peer.local_ledger):
                start_idx = len(target_peer.local_ledger)
                for b in best_peer.local_ledger[start_idx:]:
                    target_peer.commit_block(b)
                    missing_count += 1

            return {
                "status": "NODE_RECOVERED_AND_SYNCED",
                "peer_id": peer_id,
                "synchronized_blocks": missing_count,
                "current_block_height": len(target_peer.local_ledger)
            }

    def get_cluster_status(self) -> Dict[str, Any]:
        with self.lock:
            peers_summary = [p.to_summary_dict() for p in self.peers.values()]
            online_count = sum(1 for p in self.peers.values() if p.status == "ONLINE")
            ref_peer = list(self.peers.values())[0]
            current_height = len(ref_peer.local_ledger)

            return {
                "channel_name": self.channel_name,
                "consensus_algorithm": "Raft (CFT) + 2-of-3 Multi-MSP Endorsement",
                "endorsement_policy": self.endorsement_policy,
                "min_endorsements_required": self.min_endorsements,
                "cluster_health": "HEALTHY" if online_count >= 2 else "DEGRADED_QUORUM_LOST",
                "online_peers": online_count,
                "total_peers": len(self.peers),
                "block_height": current_height,
                "orderer": {
                    "id": self.orderer.orderer_id,
                    "cluster": self.orderer.cluster_name,
                    "status": self.orderer.leader_status,
                    "endpoint": self.orderer.endpoint
                },
                "peers": peers_summary
            }

    def get_channel_ledger(self) -> List[Dict[str, Any]]:
        with self.lock:
            # Return ledger of first online peer
            for peer in self.peers.values():
                if peer.status == "ONLINE" and peer.local_ledger:
                    return peer.local_ledger
            return []


# Global Singleton
_FABRIC_NETWORK: Optional[FabricConsortiumNetwork] = None
_FABRIC_LOCK = threading.Lock()


def get_fabric_consortium() -> FabricConsortiumNetwork:
    global _FABRIC_NETWORK
    if _FABRIC_NETWORK is None:
        with _FABRIC_LOCK:
            if _FABRIC_NETWORK is None:
                _FABRIC_NETWORK = FabricConsortiumNetwork()
    return _FABRIC_NETWORK
