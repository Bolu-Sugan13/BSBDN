"""
Blockchain Module
------------------
A lightweight, SHA-256 based blockchain simulation used to make every
health-record update tamper-evident. Each block stores a hash of its
own data plus the hash of the previous block, forming a chain. If any
stored record is edited after the fact, its recomputed hash will no
longer match what was originally stored, and the chain link will break
at that point — this is what the Admin integrity check detects.
"""

import hashlib
import json
import time
import sqlite3
import database as db


class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data  # dict: patient_id, record_type, payload
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self):
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )
        return hashlib.sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


def genesis_block():
    return Block(0, time.time(), {"info": "Genesis Block - BSBDN chain initialized"}, "0" * 64)


def create_block(index, data, previous_hash):
    return Block(index, time.time(), data, previous_hash)


def add_block_safe(data, timeout=10.0, max_retries=3):
    """
    Safely creates and commits a new block inside an exclusive BEGIN IMMEDIATE
    transaction, retrying if contention occurs. Enforces UNIQUE(idx) and strictly
    sequential previous_hash linking.
    Returns: (block: Block, block_id: int)
    """
    for attempt in range(max_retries):
        try:
            with db.db_immediate_session(timeout=timeout) as conn:
                last_block = conn.execute("SELECT * FROM blocks ORDER BY idx DESC LIMIT 1").fetchone()
                if not last_block:
                    g = genesis_block()
                    cur = conn.execute(
                        "INSERT INTO blocks (idx, timestamp, data, previous_hash, hash) VALUES (?, ?, ?, ?, ?)",
                        (g.index, g.timestamp, json.dumps(g.data) if isinstance(g.data, dict) else g.data,
                         g.previous_hash, g.hash),
                    )
                    return g, cur.lastrowid

                new_idx = last_block["idx"] + 1
                prev_hash = last_block["hash"]
                blk = create_block(new_idx, data, prev_hash)
                cur = conn.execute(
                    "INSERT INTO blocks (idx, timestamp, data, previous_hash, hash) VALUES (?, ?, ?, ?, ?)",
                    (blk.index, blk.timestamp, json.dumps(blk.data) if isinstance(blk.data, dict) else blk.data,
                     blk.previous_hash, blk.hash),
                )
                return blk, cur.lastrowid
        except sqlite3.OperationalError as e:
            if "locked" in str(e).lower() or "busy" in str(e).lower():
                time.sleep(0.05 * (attempt + 1))
                continue
            raise
    raise RuntimeError("Failed to acquire database lock for block creation after maximum retries.")



def recompute_hash(index, timestamp, data, previous_hash):
    """Recompute a block's hash from stored fields, for integrity verification."""
    block_string = json.dumps(
        {"index": index, "timestamp": timestamp, "data": data, "previous_hash": previous_hash},
        sort_keys=True,
    )
    return hashlib.sha256(block_string.encode()).hexdigest()


def verify_chain(blocks):
    """
    blocks: list of dicts (as stored in DB), ordered by idx ascending.
    Returns (is_valid: bool, broken_at: int|None, report: list[dict])
    """
    report = []
    is_valid = True
    broken_at = None

    for i, b in enumerate(blocks):
        data = json.loads(b["data"]) if isinstance(b["data"], str) else b["data"]
        expected_hash = recompute_hash(b["idx"], b["timestamp"], data, b["previous_hash"])
        hash_ok = expected_hash == b["hash"]

        link_ok = True
        if i > 0:
            link_ok = b["previous_hash"] == blocks[i - 1]["hash"]

        ok = hash_ok and link_ok
        if not ok and is_valid:
            is_valid = False
            broken_at = b["idx"]

        report.append(
            {
                "idx": b["idx"],
                "hash_ok": hash_ok,
                "link_ok": link_ok,
                "stored_hash": b["hash"],
                "expected_hash": expected_hash,
            }
        )

    return is_valid, broken_at, report
