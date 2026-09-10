"""
Unit & Integration Tests for Hyperledger Fabric Cross-CII Consortium.
Tests:
- 3-Substation Peer Initialization & Genesis Block
- 2-of-3 Multi-MSP Endorsement Policy Verification
- Raft Orderer Merkle Root & Block Packaging
- Gossip Block Replication across Peers
- Fault Tolerance (Network cut on 1 peer, consensus still succeeds with 2/3)
- Substation Recovery & Gossip Catch-up Sync
"""

import pytest
from src.ledger.fabric_network import FabricConsortiumNetwork, _compute_merkle_root


def test_genesis_block_and_peers():
    network = FabricConsortiumNetwork()
    status = network.get_cluster_status()

    assert status["channel_name"] == "cross-cii-grid-defense-channel"
    assert status["total_peers"] == 3
    assert status["online_peers"] == 3
    assert status["block_height"] == 1  # Genesis block committed
    assert status["cluster_health"] == "HEALTHY"

    # Verify all 3 substations have the exact same genesis block
    b0_hashes = [p.local_ledger[0]["block_hash"] for p in network.peers.values()]
    assert len(set(b0_hashes)) == 1, "Genesis block hash mismatch across substations!"


def test_cross_cii_propose_and_commit():
    network = FabricConsortiumNetwork()

    result = network.propose_and_commit_threat_ioc(
        proposing_peer_id="peer0.wardha.grid",
        threat_type="DDoS-SYN-Flood",
        adversary_ip="192.168.1.105",
        target_asset="Wardha 765kV SCADA RTU",
        mitre_stage="Impact (TA0040)",
        confidence=0.96,
        proposed_action="DENY_INGRESS_DROP"
    )

    assert result["status"] == "CONSENSUS_COMMITTED"
    assert result["block_index"] == 1
    assert result["endorsing_peers_count"] == 3
    assert len(result["endorsing_msps"]) == 3
    assert "WardhaMSP" in result["endorsing_msps"]
    assert "JabalpurMSP" in result["endorsing_msps"]
    assert "IndoreMSP" in result["endorsing_msps"]

    # Verify all peers committed block 1 with identical block hash and Merkle root
    peer_hashes = [p.local_ledger[1]["block_hash"] for p in network.peers.values()]
    assert len(set(peer_hashes)) == 1
    assert network.get_cluster_status()["block_height"] == 2


def test_merkle_root_computation():
    leaves = ["hash_tx_1", "hash_tx_2", "hash_tx_3"]
    root = _compute_merkle_root(leaves)
    assert isinstance(root, str)
    assert len(root) == 64

    # Order and deterministic check
    root2 = _compute_merkle_root(leaves)
    assert root == root2


def test_byzantine_fault_tolerance_with_partitioned_node():
    network = FabricConsortiumNetwork()

    # Partition 1 substation (e.g. Jabalpur offline due to fiber cut)
    part_res = network.simulate_partition("peer0.jabalpur.grid")
    assert part_res["status"] == "NODE_PARTITIONED"
    assert part_res["active_online_nodes"] == 2

    # Consensus must STILL SUCCEED because 2 of 3 nodes (Wardha + Indore) meet policy!
    result = network.propose_and_commit_threat_ioc(
        proposing_peer_id="peer0.wardha.grid",
        threat_type="PortScan-Recon",
        adversary_ip="10.0.0.88",
        target_asset="Indore Feeder 4",
        mitre_stage="Reconnaissance (TA0043)",
        confidence=0.88
    )

    assert result["status"] == "CONSENSUS_COMMITTED"
    assert result["endorsing_peers_count"] == 2
    assert "JabalpurMSP" not in result["endorsing_msps"]
    assert "WardhaMSP" in result["endorsing_msps"]
    assert "IndoreMSP" in result["endorsing_msps"]

    # Now partition a second substation (only 1 remains) -> Quorum lost!
    network.simulate_partition("peer0.indore.grid")
    failed_res = network.propose_and_commit_threat_ioc(
        proposing_peer_id="peer0.wardha.grid",
        threat_type="Infiltration",
        adversary_ip="172.16.0.99",
        target_asset="Wardha Gateway",
        mitre_stage="Initial Access",
        confidence=0.92
    )

    assert failed_res["status"] == "CONSENSUS_REJECTED"
    assert "Endorsement policy unmet" in failed_res["reason"]


def test_substation_recovery_and_catch_up_sync():
    network = FabricConsortiumNetwork()

    # Partition Indore
    network.simulate_partition("peer0.indore.grid")

    # Commit 2 blocks while Indore is offline
    network.propose_and_commit_threat_ioc("peer0.wardha.grid", "Attack-1", "10.1.1.1", "T1", "Stage", 0.95)
    network.propose_and_commit_threat_ioc("peer0.jabalpur.grid", "Attack-2", "10.1.1.2", "T2", "Stage", 0.95)

    assert len(network.peers["peer0.wardha.grid"].local_ledger) == 3  # Genesis + 2
    assert len(network.peers["peer0.indore.grid"].local_ledger) == 1  # Only Genesis

    # Recover Indore
    rec_res = network.recover_node("peer0.indore.grid")
    assert rec_res["status"] == "NODE_RECOVERED_AND_SYNCED"
    assert rec_res["synchronized_blocks"] == 2
    assert rec_res["current_block_height"] == 3

    # Verify hashes match Wardha exactly
    assert network.peers["peer0.indore.grid"].local_ledger[-1]["block_hash"] == network.peers["peer0.wardha.grid"].local_ledger[-1]["block_hash"]
