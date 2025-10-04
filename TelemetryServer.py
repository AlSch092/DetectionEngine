# telemetry_server.py
from flask import Flask, request, jsonify
import sqlite3, json, time, threading, queue, atexit, os, signal

DB_PATH = "telemetry.db"
BATCH_SIZE = 500           # max rows per flush
FLUSH_MS = 120             # flush at most every 120ms
QUEUE_MAX = 10000          # backpressure if storm
ALLOW_ACTION_STRINGS = {"None":0,"Open":1,"Close":2,"Load":3,"Unload":4,"SelfShutdown":5, "Heartbeat":6, "Flag":7, "SuspiciousProgram":8, "TerminatedProcess":9, "ProgramError": 10 }
ALLOW_ACTION_STRINGS_CODES = {v: k for k, v in ALLOW_ACTION_STRINGS.items()}

HEARTBEAT_TIMEOUT_MS = 180_000   # 2 minutes
SWEEP_PERIOD_MS      = 10_000     # run offline sweeper every 5s

DETECTION_FLAGS = {0: "NONE",1: "UNKNOWN",2: "EXECUTION_ERROR",1000: "PAGE_PROTECTIONS",1001: "CODE_INTEGRITY",1002: "GAME_PROCESS_CODE_INTEGRITY", 1003: "DLL_TAMPERING", 1004: "HOOKED_IAT",    1005: "OPEN_PROCESS_HANDLES",    1006: "UNSIGNED_DRIVERS",    1007: "LOADED_UNSIGNED_MODULE",    1008: "LOADED_GAME_UNSIGNED_MODULE",    1009: "INJECTED_ILLEGAL_PROGRAM",    1010: "EXTERNAL_ILLEGAL_PROGRAM",    1011: "MANUAL_MAPPED_MEMORY",    1012: "FLAGGED_DRIVER",    1013: "FLAGGED_EXE",    1014: "SECURE_BOOT_DISABLED",    1015: "PROCESS_NOT_ADMIN",    1016: "PYTHON_SCRIPT",    1017: "PACKAGED_PYTHON_EXE",    1018: "BLACKLISTED_WINDOW_TEXT",    1019: "BLACKLISTED_BYTE_PATTERN",    1020: "BLACKLISTED_FILE_CRC32",    1021: "BLACKLISTED_DATA_STRING",    1022: "BLACKLISTED_COMMAND_LINE",    1023: "BLACKLISTED_NETWORK_CONNECTION",    1024: "FLAGGED_HARDWARE",    1025: "THREAD_SUSPENDED",    1026: "HYPERVISOR",    1027: "HVCI_DISABLED",    1028: "REGISTRY_KEY_MODIFICATIONS",    1029: "TEST_SIGNING_MODE",    1030: "DEBUG_MODE", 1031: "WINDOWS_VERSION_BELOW_10",1032: "VULNERABLE_DRIVER_LIST_DISABLED",1033: "WMI_NOT_STARTABLE", 1034: "WMI_DISABLED", 1035: "HIGH_GPU_USAGE", 1036: "HIGH_CPU_USAGE", 10000: "DEBUG_WINAPI_DEBUGGER",    10001: "DEBUG_PEB",    10002: "DEBUG_HARDWARE_REGISTERS",    10003: "DEBUG_HEAP_FLAG",    10004: "DEBUG_INT3",    10005: "DEBUG_INT2C",    10006: "DEBUG_INT2D",    10007: "DEBUG_CLOSEHANDLE",    10008: "DEBUG_DEBUG_OBJECT",    10009: "DEBUG_VEH_DEBUGGER",    10010: "DEBUG_KERNEL_DEBUGGER",    10011: "DEBUG_TRAP_FLAG",    10012: "DEBUG_DEBUG_PORT",    10013: "DEBUG_PROCESS_DEBUG_FLAGS",    10014: "DEBUG_REMOTE_DEBUGGER",    10015: "DEBUG_DBK64_DRIVER",    10016: "DEBUG_KNOWN_DEBUGGER_PROCESS" }


# --- DB init (WAL + schema + indices) ---
def init_db():
    need_init = not os.path.exists(DB_PATH)
    con = sqlite3.connect(DB_PATH)
    con.execute("PRAGMA journal_mode=WAL;")
    con.execute("PRAGMA synchronous=NORMAL;")
    con.execute("PRAGMA temp_store=MEMORY;")
    # optional mmap on 64-bit
    try: con.execute("PRAGMA mmap_size=3221225472;")  # 3GB
    except: pass

    con.execute("""
    CREATE TABLE IF NOT EXISTS online_users(
        client_id      TEXT PRIMARY KEY,
        first_seen_ms  INTEGER NOT NULL,
        last_seen_ms   INTEGER NOT NULL,
        is_online      INTEGER NOT NULL DEFAULT 1,   -- 1=online, 0=offline
        flagged_ms     INTEGER,                      -- when we flagged due to timeout
        flag_reason    TEXT
    );
    """)
    con.execute("CREATE INDEX IF NOT EXISTS ix_online_last_seen ON online_users(last_seen_ms);")

    con.execute("""
    CREATE TABLE IF NOT EXISTS events(
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        ts_ms        INTEGER NOT NULL,          -- event time (ms since epoch)
        ingest_ms    INTEGER NOT NULL,          -- server receive time (ms)
        event_id     INTEGER NOT NULL,
        client_id    INTEGER NOT NULL,
        action       INTEGER NOT NULL,          -- 0..10
        flag_id      INTEGER,
        process_id   INTEGER NOT NULL,
        process_path TEXT NOT NULL,
        raw_json     BLOB NOT NULL              -- raw body for forensics
    );
    """)
    # Fast common lookups:
    con.execute("CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts_ms);")
    con.execute("CREATE INDEX IF NOT EXISTS ix_events_client_ts ON events(client_id, ts_ms);")
    con.execute("CREATE INDEX IF NOT EXISTS ix_events_action_ts ON events(action, ts_ms);")
    # Soft de-dup: same (event_id, process_id, action)
    con.execute("""
    CREATE UNIQUE INDEX IF NOT EXISTS uq_event_triplet
    ON events(event_id, process_id, action, flag_id);
    """)
    con.commit()
    con.close()

# --- Writer thread (only owner of the DB connection) ---
class DBWriter(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.q = queue.Queue(maxsize=QUEUE_MAX)
        self._stop = threading.Event()
        self.con = None

    def run(self):
        self.con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        self.con.execute("PRAGMA journal_mode=WAL;")
        self.con.execute("PRAGMA synchronous=NORMAL;")
        cur = self.con.cursor()

        pending = []
        last_flush = time.time()

        while not self._stop.is_set():
            tnow = time.time()
            timeout = max(0.0, (FLUSH_MS/1000.0) - (tnow - last_flush))
            try:
                item = self.q.get(timeout=timeout)
                pending.append(item)
            except queue.Empty:
                pass

            # flush on size or time
            if pending and (len(pending) >= BATCH_SIZE or (time.time() - last_flush) >= (FLUSH_MS/1000.0)):
                try:
                    cur.executemany("""
                        INSERT OR IGNORE INTO events
                        (ts_ms, ingest_ms, event_id, client_id, action, flag_id, process_id, process_path, raw_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, pending)
                    self.con.commit()
                except sqlite3.Error as e:
                    # If something goes wrong, drop the batch (but log) to keep service alive
                    print("DB batch insert error:", e)
                pending.clear()
                last_flush = time.time()

        # final drain
        while True:
            try:
                pending.append(self.q.get_nowait())
            except queue.Empty:
                break
        if pending:
            try:
                cur.executemany("""
                    INSERT OR IGNORE INTO events
                    (ts_ms, ingest_ms, event_id, client_id, action, flag_id, process_id, process_path, raw_json)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, pending)
                self.con.commit()
            except sqlite3.Error as e:
                print("DB final flush error:", e)
        self.con.close()

    def stop(self):
        self._stop.set()

class OnlineTracker(threading.Thread):
    """
    Maintains online_users.last_seen_ms and flips users offline when
    they miss heartbeats for > HEARTBEAT_TIMEOUT_MS. When it flips a user
    offline, it also enqueues a 'Flag' event into the main writer.
    """
    def __init__(self):
        super().__init__(daemon=True)
        self.q = queue.Queue(maxsize=QUEUE_MAX)
        self._stop = threading.Event()
        self.con = None

    def run(self):
        self.con = sqlite3.connect(DB_PATH, timeout=30, isolation_level=None)
        self.con.execute("PRAGMA journal_mode=WAL;")
        self.con.execute("PRAGMA synchronous=NORMAL;")
        cur = self.con.cursor()

        last_sweep = 0
        while not self._stop.is_set():
            # Drain small bursts of updates (non-blocking)
            updates = []
            try:
                item = self.q.get(timeout=SWEEP_PERIOD_MS / 1000.0)
                updates.append(item)
                while len(updates) < 1000:
                    updates.append(self.q.get_nowait())
            except queue.Empty:
                pass

            # Apply updates (upsert last_seen + set online=1)
            if updates:
                norm = []
                for it in updates:
                    if len(it) == 2:
                        cid, ms = it
                        norm.append((cid, ms, ms))
                    else:
                        norm.append(it)
                        
                try:
                    cur.executemany("""
                        INSERT INTO online_users (client_id, first_seen_ms, last_seen_ms, is_online)
                        VALUES (?, ?, ?, 1)
                        ON CONFLICT(client_id) DO UPDATE SET
                            last_seen_ms = excluded.last_seen_ms,
                            is_online    = 1
                    """, norm)
                    self.con.commit()
                except sqlite3.Error as e:
                    print("OnlineTracker upsert error:", e)

            # Periodic sweep to mark offline + flag
            now = now_ms()
            if now - last_sweep >= SWEEP_PERIOD_MS:
                try:
                    stale = list(cur.execute("""
                        SELECT client_id, last_seen_ms
                        FROM online_users
                        WHERE is_online=1 AND (? - last_seen_ms) > ?
                    """, (now, HEARTBEAT_TIMEOUT_MS)))

                    if stale:
                        # Flip to offline + record flag meta
                        cur.executemany("""
                            UPDATE online_users
                            SET is_online=0, flagged_ms=?, flag_reason='heartbeat timeout (>2m)'
                            WHERE client_id=?
                        """, ((now, cid) for (cid, _) in stale))
                        self.con.commit()

                        # Emit a Flag event for each
                        try:
                            for (cid, _) in stale:
                                raw_obj = {
                                    "auto_generated": True,
                                    "reason": "heartbeat timeout (>2m)",
                                    "client_id": cid
                                }
                                raw_json = json.dumps(raw_obj, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
                                # Make an event id that's unique-ish (monotonic) for dedup index
                                ev_id = int(now)  # fine if flipping a few at the same ms; your unique index is on (event_id, process_id, action)
                                row = (
                                    now,                    # ts_ms
                                    now,                    # ingest_ms
                                    ev_id,                  # event_id
                                    cid,                    # client_id
                                    ALLOW_ACTION_STRINGS["Flag"],  # action
                                    0,
                                    0,                      # process_id
                                    "server",               # process_path
                                    raw_json                # raw_json
                                )
                                # Put into the existing writer (best-effort)
                                if writer:
                                    try:
                                        writer.q.put_nowait(row)
                                    except queue.Full:
                                        # If full, skip; the offline state is already persisted
                                        pass
                        except Exception as e:
                            print("OnlineTracker flag enqueue error:", e)

                except sqlite3.Error as e:
                    print("OnlineTracker sweep error:", e)
                finally:
                    last_sweep = now

    def stop(self):
        self._stop.set()

tracker = None
writer = None

def start_writer():
    global writer
    init_db()
    writer = DBWriter()
    writer.start()

def stop_writer():
    if writer:
        writer.stop()
        writer.join(timeout=3)

def start_tracker():
    global tracker
    tracker = OnlineTracker()
    tracker.start()

def stop_tracker():
    if tracker:
        tracker.stop()
        tracker.join(timeout=3)

# --- Flask app ---
app = Flask(__name__)

def now_ms():
    return int(time.time() * 1000)

def parse_action(val):
    # Accept strings or ints; normalize to 0..N
    if isinstance(val, int):
        if 0 <= val <= 10:
            return val
        raise ValueError("action int out of range 0..10")
    if isinstance(val, str):
        if val in ALLOW_ACTION_STRINGS:
            return ALLOW_ACTION_STRINGS[val]
        raise ValueError("unknown action string")
    raise ValueError("invalid action type")

# Accept int (0..8), numeric strings, or known names (includes Heartbeat/Flag)
def normalize_action(val):
    if isinstance(val, int):
        if 0 <= val <= 10: 
            return val
        raise ValueError("action int out of range 0..10")
    if isinstance(val, str):
        s = val.strip()
        if s.isdigit():
            i = int(s)
            if 0 <= i <= 10:
                return i
            raise ValueError("action numeric string out of range 0..10")
        if s in ALLOW_ACTION_STRINGS:
            return ALLOW_ACTION_STRINGS[s]
        raise ValueError(f"unknown action string: {s}")
    raise ValueError("invalid action type")

@app.route("/v1/PushTelemetry", methods=["POST"])
def push_telemetry():
    try:
        payload = request.get_json(force=True, silent=False)
        if payload is None:
            return jsonify({"status": "error", "message": "invalid or empty JSON"}), 400

        def enqueue_one(d: dict):
            # Required fields
            event_id     = int(d["event_id"])
            client_id    = str(d["client_id"])
            action_code  = normalize_action(d.get("action", 0))
            flag_id         = int(d["flag_id"])
            process_id   = int(d["process_id"])
            pp           = d.get("process_path")
            process_path = str(pp) if pp is not None else ""     # avoid NOT NULL violation
            ts_ms        = int(d.get("timestamp", now_ms()))
            ingest_ms    = now_ms()
            
            # tell the OnlineTracker this client is alive *now*
            # we update last_seen on ANY event; if you only want on Heartbeat, gate by action_code
            seen_ms = ts_ms if ts_ms <= ingest_ms else ingest_m
            try:
                if action_code == ALLOW_ACTION_STRINGS["Heartbeat"] and tracker:
                    tracker.q.put_nowait((client_id, ingest_ms, ingest_ms))
            except queue.Full:
                pass
            
            print(f"ClientId: {client_id} sent event {event_id}, flag: {DETECTION_FLAGS[flag_id]}, action: {ALLOW_ACTION_STRINGS_CODES[action_code]}, path: {process_path}")
            raw = json.dumps(d, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            row = (ts_ms, ingest_ms, event_id, client_id, action_code, flag_id, process_id, process_path, raw)
            writer.q.put_nowait(row)

        if isinstance(payload, list):
            print(f"Received batch: {len(payload)} events")
            for idx, item in enumerate(payload):
                if not isinstance(item, dict):
                    return jsonify({"status": "error", "message": f"element {idx} is not an object"}), 400
                try:
                    enqueue_one(item)   # <-- use item, not data
                except KeyError as ke:
                    # Identify exactly which field/element failed
                    print(f"Bad element {idx}: missing field {ke}")
                    return jsonify({"status": "error",
                                    "message": f"element {idx}: missing field {str(ke)}"}), 400
                except ValueError as ve:
                    print(f"Bad element {idx}: {ve}")
                    return jsonify({"status": "error",
                                    "message": f"element {idx}: {ve}"}), 400
        elif isinstance(payload, dict):
            print("Received single event")
            enqueue_one(payload)
        else:
            return jsonify({"status": "error", "message": "JSON must be object or array"}), 400

        return jsonify({"status": "ok"}), 200

    except queue.Full:
        # Proper backpressure signal for the client to retry
        return jsonify({"status": "busy", "retry_ms": 500}), 503
    except Exception as e:
        # Last-resort: print the offending body for diagnosis
        print("Unhandled error:", e)
        try:
            print("Body:", request.data[:2048])
        except Exception:
            pass
        return jsonify({"status": "error", "message": str(e)}), 400
  
@app.route("/v1/healthz", methods=["GET"])
def healthz():
    return jsonify({
        "ok": True,
        "queue_len": writer.q.qsize() if writer else -1
    }), 200

@app.route("/v1/online", methods=["GET"])
def online():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("""
        SELECT client_id, first_seen_ms, last_seen_ms, is_online, flagged_ms, flag_reason
        FROM online_users
        ORDER BY last_seen_ms DESC
        LIMIT 200
    """).fetchall()
    con.close()
    return jsonify([dict(r) for r in rows]), 200

@app.route("/v1/version", methods=["GET"])
def version():
    return "100", 200


def _graceful_shutdown(*_):
    stop_tracker()
    stop_writer()
    os._exit(0)

if __name__ == "__main__":
    start_writer()
    start_tracker()
    atexit.register(stop_writer)
    try:
        signal.signal(signal.SIGTERM, _graceful_shutdown)
        signal.signal(signal.SIGINT, _graceful_shutdown)
    except Exception:
        pass
    # Use a single process (no gunicorn workers) if sticking with SQLite.
    app.run(host="0.0.0.0", port=5002, threaded=True)
