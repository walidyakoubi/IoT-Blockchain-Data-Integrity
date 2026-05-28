"""
Background loop that re-verifies aging readings against the Fabric ledger.
Runs continuously alongside the ingestion service.

Why this process exists:
  The ingestion service verifies each row ONCE, immediately after anchoring.
  After that, nothing in the pipeline would catch a row that was tampered
  with later (e.g. someone running an UPDATE directly against SQLite).

  This loop closes that gap. Every LOOP_SLEEP_S seconds, it pulls the
  oldest BATCH_SIZE rows whose verdict is older than RECHECK_AGE_S seconds
  and re-asks Fabric: "is the hash you stored still equal to the hash
  currently in SQLite?". A change of verdict (intact → tampered) is logged
  with a 🚨 STATE CHANGE marker — that line is the demonstrable proof of
  tamper detection during the soutenance demo.

  Ledger lookups are keyed by (device_id, ts, seq) — the same composite
  used by the ingestion service when calling store_hash. Both paths must
  agree on this triple or every re-verification will return "not found".
"""
import sqlite3, time, sys, os
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fabric_client import verify_hash

DB_PATH       = Path(__file__).resolve().parents[1] / "db" / "iot.db"
RECHECK_AGE_S = 60     # re-verify rows whose verdict is older than this
LOOP_SLEEP_S  = 30     # how often the loop wakes up
BATCH_SIZE    = 50     # max rows re-verified per iteration


def fetch_aging_rows():
    """
    Pull rows whose verdict is older than RECHECK_AGE_S.

    We deliberately exclude:
      - 'pending' : ingestion service is still working on these (race)
      - 'failed'  : Fabric was unreachable when ingested; needs a separate
                    retry mechanism, not the periodic re-check loop
    """
    cutoff = int(time.time()) - RECHECK_AGE_S
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        """
        SELECT device_id, ts, seq, payload_hash, verified
          FROM readings
         WHERE verified_at < ?
           AND verified IN ('intact', 'tampered')
         ORDER BY verified_at ASC
         LIMIT ?
        """,
        (cutoff, BATCH_SIZE),
    ).fetchall()
    con.close()
    return [dict(r) for r in rows]


def update_verdict(device_id: str, ts: int, seq: int,
                   verdict: str, old_verdict: str):
    """
    Persist the new verdict + verified_at. A change of verdict is the
    interesting event — log it loudly so it is visible in the terminal
    during the demo.

    WHERE filters on (device_id, ts, seq) — the same triple that
    uniquely identifies a reading everywhere else in the pipeline.
    """
    con = sqlite3.connect(DB_PATH)
    con.execute(
        "UPDATE readings "
        "SET verified=?, verified_at=? "
        "WHERE device_id=? AND ts=? AND seq=?",
        (verdict, int(time.time()), device_id, ts, seq),
    )
    con.commit()
    con.close()
    if verdict != old_verdict:
        print(f"[Reverifier] 🚨 STATE CHANGE {device_id} ts={ts} seq={seq}: "
              f"{old_verdict} → {verdict}")
    else:
        print(f"[Reverifier] {device_id} ts={ts} seq={seq} still {verdict}")


def main():
    print(f"[Reverifier] Started. Re-checking rows older than "
          f"{RECHECK_AGE_S}s every {LOOP_SLEEP_S}s.")
    while True:
        try:
            rows = fetch_aging_rows()
            if rows:
                print(f"[Reverifier] Re-checking {len(rows)} rows...")
            for r in rows:
                intact = verify_hash(
                    r["device_id"], r["ts"], r["payload_hash"], r["seq"],
                )
                verdict = ("intact"   if intact is True
                           else "tampered" if intact is False
                           else "failed")
                update_verdict(
                    r["device_id"], r["ts"], r["seq"],
                    verdict, r["verified"],
                )
        except Exception as e:
            # Defensive: a single bad row must not kill the loop
            import traceback
            print(f"[Reverifier] ❌ {type(e).__name__}: {e}")
            traceback.print_exc()
        time.sleep(LOOP_SLEEP_S)


if __name__ == "__main__":
    main()