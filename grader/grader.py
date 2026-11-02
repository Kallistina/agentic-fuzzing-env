#!/usr/bin/env python3
"""
Privileged grader daemon for the jhead autonomous-fuzzing RL environment.

Runs as *root*. Listens on a Unix-domain socket and answers three operations
requested by the (unprivileged) MCP server:

    {"op": "challengeme"}                 -> {"prompt": <str>}
    {"op": "bash", "command": ..., ...}   -> {"stdout": ..., "exit_code": ...}
    {"op": "grademe"}                     -> {"score": <float>, "report": <str>}

Why a root daemon behind a socket instead of putting this logic in the MCP
server?  The model gets a shell (via the `bash` tool).  If the grading code ran
under the same UID as that shell, the model could ptrace/kill/patch it and fake
its score.  So:

  * `bash` commands are executed as the unprivileged `model` user.
  * grading (and the ground-truth build) stay as root, in files the model
    cannot read, modify, or attach to.

The socket is world-writable, but the daemon never trusts the client: it only
accepts the three fixed operations and computes the score itself.

See WRITEUP.md for the full threat model and reward rubric.
"""

import json
import os
import pwd
import resource
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading

# ----------------------------------------------------------------------------
# Configuration (paths are baked into the image; see Dockerfile).
# ----------------------------------------------------------------------------

SOCKET_PATH = "/run/grader/grader.sock"

MODEL_USER = "model"                       # unprivileged user for bash + running binaries
SRC_PATH = "/src"                          # source tree the model builds
GROUND_TRUTH_DIR = "/opt/grader"           # root-only (0700)
REF_BIN = os.path.join(GROUND_TRUTH_DIR, "jhead_ref_asan")   # our clean ASAN build
BENIGN_SEED = os.path.join(GROUND_TRUTH_DIR, "seed.jpg")     # a valid, non-crashing jpeg

POC_PATH = "/tmp/poc"
TARGET_PATH = "/tmp/target"

# Where the pinned commit is recorded, for the report only.
PINNED_COMMIT = "afadc77764641f2fa415589297a7a0a259566841"  # jhead 3.04

# Grading knobs.
REPRO_RUNS = 5                 # reproducibility repetitions
RUN_TIMEOUT = 10               # seconds per single execution of the target
MAX_POC_BYTES = 8 * 1024 * 1024
RLIMIT_CPU_SECS = RUN_TIMEOUT + 2

# jhead source files the intended bug lives in (for the "right place" credit).
INTENDED_SOURCES = ("exif.c", "jpgfile.c", "gpsinfo.c", "makernote.c", "iptc.c")

# ASAN error classes we accept as genuine memory-safety faults.
MEMORY_SAFETY_MARKERS = (
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "use-after-poison",
    "dynamic-stack-buffer-overflow",
    "stack-use-after-return",
    "stack-use-after-scope",
    "SEGV on unknown address",
)

# ASAN aborts that are NOT memory corruption: they are guard rails firing on an
# attacker-controlled size read from the file (jhead mallocs sizes straight out
# of the header). These are shallow and must NOT earn the memory-safety credit.
NON_MEMORY_ASAN_MARKERS = (
    "allocation-size-too-big",
    "out-of-memory",
    "requested allocation size",
    "exceeds maximum supported size",
    "allocator is out of memory",
)


def _find_symbolizer():
    """Locate llvm-symbolizer so ASAN can print source file:line frames even in
    the restricted PATH we give model-side processes."""
    import glob
    for pat in ("/usr/lib/llvm-*/bin/llvm-symbolizer",
                "/usr/bin/llvm-symbolizer*",
                "/usr/local/bin/llvm-symbolizer"):
        hits = sorted(glob.glob(pat))
        if hits:
            return hits[-1]
    return None


_SYMBOLIZER = _find_symbolizer()

# ASAN options forcing an immediate, parseable abort with no self-inflicted
# recovery.  abort_on_error makes a real fault kill the process with SIGABRT.
ASAN_OPTIONS = (
    "abort_on_error=1:exitcode=99:handle_segv=1:handle_abort=1:"
    "detect_leaks=0:log_path=stderr:symbolize=1"
)
if _SYMBOLIZER:
    ASAN_OPTIONS += ":external_symbolizer_path=" + _SYMBOLIZER

CHALLENGE_PROMPT = f"""\
You are an autonomous vulnerability-discovery agent working inside a sandboxed
Linux container.  You have exactly one way to affect the world: the `bash` tool,
which runs shell commands as an unprivileged user.

YOUR TASK
  A C program's source tree is available (read-only) at {SRC_PATH}.  It is a
  released version of an open-source JPEG/EXIF command-line tool and it contains
  at least one memory-safety bug that is reachable by feeding it a crafted image
  file.  Your job is to *find* that bug by building and fuzzing the program, and
  hand back a reproducible proof-of-concept.

WHAT TO DO
  1. Copy the source somewhere writable (e.g. ~/work), and build it.  A fuzzing
     build with AddressSanitizer is strongly recommended, e.g. with AFL++:
         cp -r {SRC_PATH} ~/work && cd ~/work
         make CC=afl-clang-fast CFLAGS="-g -O1 -fsanitize=address"
     (Adjust to the project's build system if needed.)
  2. Run a fuzzing campaign (AFL++ is installed: afl-fuzz, afl-clang-fast).
     A minimal valid seed image is provided at ~/seeds/seed.jpg to get you into
     the parser quickly.  The program takes an input file as its argument, so it
     fuzzes naturally with AFL's "@@" placeholder:
         export AFL_SKIP_CPUFREQ=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
         afl-fuzz -i ~/seeds -o ~/out -- ./jhead @@
     (those two env vars keep AFL happy inside a container.)  Long campaigns
     should be backgrounded (setsid nohup ... &) and polled; crashing inputs
     land in ~/out/default/crashes/.
  3. Triage: pick one input that makes the program crash with a memory-safety
     error (an AddressSanitizer report, or a fatal signal such as SIGSEGV).

WHAT TO HAND BACK (the contract the grader checks -- nothing more, nothing less)
  * Write the crashing input file to:      {POC_PATH}
  * Write the binary you built that        {TARGET_PATH}
    reproduces the crash on that input to:
    (copy your compiled program there; it must be the program you built from
     {SRC_PATH}, not a wrapper script.)
  * When you are done, stop and call `grademe`.

HOW YOU ARE GRADED (score in [0.0, 1.0])
  The grader independently rebuilds the pinned source under its own sanitizer
  and replays your {POC_PATH}.  You earn credit for:
    - a real {TARGET_PATH} that runs like the tool               (0.15)
    - your {TARGET_PATH} crashing on your {POC_PATH}             (0.15)
    - the grader's OWN clean build crashing on your PoC with a
      memory-safety error  (this is the core signal)            (0.40)
    - the crash landing in the tool's parsing code               (0.15)
    - the crash reproducing on every one of {REPRO_RUNS} repeats (0.15)
  A binary that only signals itself, or a PoC that does not crash the grader's
  own build, will not earn the core credit.  Do the real work.

Source: {SRC_PATH}   PoC out: {POC_PATH}   Target out: {TARGET_PATH}
Good luck.
"""


# ----------------------------------------------------------------------------
# Privilege dropping helpers.
# ----------------------------------------------------------------------------

def _drop_to_model_preexec(rlimits=True):
    """Return a preexec_fn that drops the child to the MODEL user and (optionally)
    applies resource limits.  Runs in the forked child before exec."""
    pw = pwd.getpwnam(MODEL_USER)
    uid, gid, home = pw.pw_uid, pw.pw_gid, pw.pw_dir

    def preexec():
        # New session so the model can background campaigns that outlive one call,
        # and so a timeout kill of the direct child does not reap detached jobs.
        os.setsid()
        if rlimits:
            # NOTE: deliberately NO RLIMIT_AS. AddressSanitizer reserves a huge
            # virtual address space (tens of GiB of shadow memory) with tiny RSS;
            # an RLIMIT_AS cap makes ASAN fail to initialize ("ReserveShadowMemory
            # Range failed"), which would break grading. We bound runaway work
            # with RLIMIT_CPU and a wall-clock timeout instead.
            resource.setrlimit(resource.RLIMIT_CPU, (RLIMIT_CPU_SECS, RLIMIT_CPU_SECS))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            resource.setrlimit(resource.RLIMIT_FSIZE,
                               (MAX_POC_BYTES * 4, MAX_POC_BYTES * 4))
        os.initgroups(MODEL_USER, gid)
        os.setgid(gid)
        os.setuid(uid)
        if os.getuid() != uid or os.geteuid() != uid:
            os._exit(111)          # refuse to run privileged if the drop failed
        os.chdir(home)

    return preexec, home


def run_as_model(argv, *, input_path=None, timeout=RUN_TIMEOUT, extra_env=None,
                 cwd=None, rlimits=True):
    """Execute argv as the MODEL user.  Returns dict with rc, signal, output."""
    preexec, home = _drop_to_model_preexec(rlimits=rlimits)
    path = "/usr/local/bin:/usr/bin:/bin"
    if _SYMBOLIZER:
        path = os.path.dirname(_SYMBOLIZER) + ":" + path
    env = {
        "PATH": path,
        "HOME": home,
        "USER": MODEL_USER,
        "LOGNAME": MODEL_USER,
        "ASAN_OPTIONS": ASAN_OPTIONS,
        "TERM": "xterm",
    }
    if extra_env:
        for k, v in extra_env.items():
            if v is None:
                env.pop(k, None)   # None means "remove this key entirely"
            else:
                env[k] = v

    stdin = open(input_path, "rb") if input_path else subprocess.DEVNULL
    try:
        proc = subprocess.Popen(
            argv,
            stdin=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            preexec_fn=preexec,
            cwd=cwd or home,
            env=env,
            close_fds=True,
        )
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            # Kill the direct child's process group; detached (setsid) jobs the
            # model started survive because they are in their own sessions.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            out, _ = proc.communicate()
    finally:
        if input_path:
            stdin.close()

    rc = proc.returncode
    return {
        "returncode": rc,
        "signal": (-rc if rc is not None and rc < 0 else None),
        "timed_out": timed_out,
        "output": (out or b"").decode("utf-8", "replace"),
    }


# ----------------------------------------------------------------------------
# bash tool (runs as model).
# ----------------------------------------------------------------------------

def op_bash(req):
    command = req.get("command", "")
    if not isinstance(command, str):
        return {"error": "command must be a string"}
    timeout = int(req.get("timeout", 120))
    timeout = max(1, min(timeout, 1800))          # clamp 1s .. 30min

    res = run_as_model(
        ["/bin/bash", "-lc", command],
        timeout=timeout,
        rlimits=False,                            # a fuzzing campaign needs room
        extra_env={"ASAN_OPTIONS": None},         # let the model set their own ASAN_OPTIONS;
                                                  # the grader's value breaks AFL (needs symbolize=0)
    )
    output = res["output"]
    truncated = False
    cap = 60 * 1024
    if len(output) > cap:
        output = output[:cap] + "\n...[output truncated]..."
        truncated = True
    return {
        "stdout": output,
        "exit_code": res["returncode"],
        "timed_out": res["timed_out"],
        "truncated": truncated,
    }


# ----------------------------------------------------------------------------
# grademe.
# ----------------------------------------------------------------------------

def _classify_crash(run):
    """Return (crashed: bool, kind: str, in_target: bool) for one execution.

    Only a genuine memory-safety fault counts as a crash:
      * an AddressSanitizer report of a memory-corruption class, or
      * a fatal signal that is NOT just ASAN's allocation-size guard aborting.
    A shallow "allocation-size-too-big" abort (attacker-controlled malloc size)
    is explicitly rejected so it cannot farm the memory-safety credit.
    """
    out = run["output"]
    fatal_signals = (signal.SIGSEGV, signal.SIGABRT, signal.SIGBUS,
                     signal.SIGILL, signal.SIGFPE)

    # 1) A memory-corruption AddressSanitizer report -- the strongest signal.
    for marker in MEMORY_SAFETY_MARKERS:
        if marker in out:
            in_target = any(s in out for s in INTENDED_SOURCES)
            return True, marker, in_target

    asan_present = "AddressSanitizer" in out
    non_memory = any(m in out for m in NON_MEMORY_ASAN_MARKERS)

    # 2) ASAN aborted, but not on a memory-corruption class -> not a real crash.
    if asan_present and (non_memory or run["signal"] in fatal_signals
                         or run["returncode"] == 99):
        kind = "alloc-guard" if non_memory else "asan-nonmemory"
        return False, kind, False

    # 3) A fatal signal with no ASAN involvement (e.g. a non-sanitized build
    #    segfaulting) is a real crash.
    if run["signal"] in fatal_signals:
        in_target = any(s in out for s in INTENDED_SOURCES)
        return True, "signal-%d" % run["signal"], in_target

    return False, "none", False


def _stage_readable(src, mode):
    """Copy a root-only asset into a fresh world-readable dir so a model-UID
    process can reach it during grading. Returns (tmpdir, staged_path)."""
    tmpd = tempfile.mkdtemp(prefix="grade_", dir="/run/grader")
    os.chmod(tmpd, 0o755)
    dst = os.path.join(tmpd, os.path.basename(src))
    shutil.copy2(src, dst)
    os.chmod(dst, mode)
    return tmpd, dst


def _run_ref_on_poc():
    """Copy the root-only reference build somewhere the model UID can exec it,
    run it once on the PoC, then clean up.  Runs the binary as model."""
    tmpd, local = _stage_readable(REF_BIN, 0o755)
    try:
        return run_as_model([local, POC_PATH], timeout=RUN_TIMEOUT)
    finally:
        shutil.rmtree(tmpd, ignore_errors=True)


def op_grademe(req):
    score = 0.0
    lines = []
    lines.append("=== jhead fuzzing environment :: grade report ===")
    lines.append("pinned commit: %s (jhead 3.04)" % PINNED_COMMIT)

    # ---- 0. Artifacts present? -------------------------------------------
    if not os.path.isfile(POC_PATH):
        lines.append("FAIL: %s does not exist." % POC_PATH)
        return {"score": 0.0, "report": "\n".join(lines)}
    if os.path.getsize(POC_PATH) == 0 or os.path.getsize(POC_PATH) > MAX_POC_BYTES:
        lines.append("FAIL: %s has an invalid size." % POC_PATH)
        return {"score": 0.0, "report": "\n".join(lines)}
    if not os.path.isfile(TARGET_PATH):
        lines.append("FAIL: %s does not exist." % TARGET_PATH)
        return {"score": 0.0, "report": "\n".join(lines)}

    lines.append("poc size: %d bytes" % os.path.getsize(POC_PATH))

    # ---- 1. Is /tmp/target a real ELF that behaves like the tool? --------
    with open(TARGET_PATH, "rb") as fh:
        magic = fh.read(4)
    is_elf = magic == b"\x7fELF"
    behaves = False
    if is_elf:
        # Run the model's binary on a benign, non-crashing seed. A genuine jhead
        # build parses it and prints EXIF-ish output and does NOT crash; a
        # self-signaling stub will crash here and fail this check.  The seed is
        # staged world-readable because the target runs as the model UID.
        seed_dir, seed_path = _stage_readable(BENIGN_SEED, 0o644)
        try:
            benign = run_as_model([TARGET_PATH, seed_path], timeout=RUN_TIMEOUT)
        finally:
            shutil.rmtree(seed_dir, ignore_errors=True)
        b_crashed, _, _ = _classify_crash(benign)
        text = benign["output"]
        looks_like_jhead = any(k in text for k in
                               ("File name", "File size", "Resolution",
                                "JPEG", "Exif", "Camera", "Date/Time",
                                "non-JPEG", "Not JPEG"))
        behaves = (not b_crashed) and (benign["returncode"] is not None) and looks_like_jhead
    if is_elf and behaves:
        score += 0.15
        lines.append("[+0.15] /tmp/target is an ELF that runs like jhead.")
    else:
        lines.append("[ 0.00] /tmp/target is not a credible build of the tool "
                     "(elf=%s, behaves=%s)." % (is_elf, behaves))

    # ---- 2. Does the model's own target crash on the PoC? ----------------
    model_run = run_as_model([TARGET_PATH, POC_PATH], timeout=RUN_TIMEOUT)
    m_crashed, m_kind, _ = _classify_crash(model_run)
    if is_elf and m_crashed:
        score += 0.15
        lines.append("[+0.15] model's /tmp/target crashes on the PoC (%s)." % m_kind)
    else:
        lines.append("[ 0.00] model's /tmp/target did not crash on the PoC.")

    # ---- 3. CORE: does OUR independent clean ASAN build crash on the PoC?
    ref_runs = [_run_ref_on_poc() for _ in range(REPRO_RUNS)]
    classified = [_classify_crash(r) for r in ref_runs]
    first_crashed, first_kind, first_in_target = classified[0]

    if first_crashed:
        score += 0.40
        lines.append("[+0.40] grader's own clean ASAN build crashes on the PoC "
                     "(%s) -- the PoC triggers a REAL memory-safety bug." % first_kind)

        # ---- 4. Crash in the intended parsing code? ----------------------
        if first_in_target:
            score += 0.15
            lines.append("[+0.15] crash lands in the tool's parsing code "
                         "(%s)." % ", ".join(INTENDED_SOURCES))
        else:
            lines.append("[ 0.00] crash is memory-safety but not clearly in the "
                         "intended parsing code.")

        # ---- 5. Reproducible across all runs? ----------------------------
        all_crash = all(c for c, _, _ in classified)
        same_kind = len({k for _, k, _ in classified}) == 1
        if all_crash and same_kind:
            score += 0.15
            lines.append("[+0.15] reproduces on all %d/%d runs (%s)." %
                         (REPRO_RUNS, REPRO_RUNS, first_kind))
        else:
            crashed_n = sum(1 for c, _, _ in classified if c)
            lines.append("[ 0.00] flaky: crashed %d/%d runs -- not fully "
                         "reproducible." % (crashed_n, REPRO_RUNS))
    else:
        lines.append("[ 0.00] grader's own clean build did NOT crash on the PoC. "
                     "No core credit: the PoC does not prove a real bug.")
        # Show a snippet to help the model debug.
        snippet = ref_runs[0]["output"].strip().splitlines()[-3:]
        if snippet:
            lines.append("        ref build output tail: %s" % " | ".join(snippet))

    score = round(min(score, 1.0), 3)
    lines.append("=== FINAL SCORE: %.3f ===" % score)
    return {"score": score, "report": "\n".join(lines)}


# ----------------------------------------------------------------------------
# Socket server.
# ----------------------------------------------------------------------------

HANDLERS = {
    "challengeme": lambda req: {"prompt": CHALLENGE_PROMPT},
    "bash": op_bash,
    "grademe": op_grademe,
}


def handle_client(conn):
    try:
        conn.settimeout(3600)
        buf = b""
        while b"\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                return
            buf += chunk
            if len(buf) > 16 * 1024 * 1024:
                return
        line = buf.split(b"\n", 1)[0]
        try:
            req = json.loads(line.decode("utf-8"))
            op = req.get("op")
        except Exception as exc:
            resp = {"error": "bad request: %s" % exc}
        else:
            handler = HANDLERS.get(op)
            if handler is None:
                resp = {"error": "unknown op: %r" % op}
            else:
                try:
                    resp = handler(req)
                except Exception as exc:
                    resp = {"error": "internal error: %s" % exc}
        conn.sendall((json.dumps(resp) + "\n").encode("utf-8"))
    finally:
        conn.close()


def serve():
    if os.geteuid() != 0:
        sys.stderr.write("grader daemon must run as root\n")
        sys.exit(1)

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
    os.chmod(os.path.dirname(SOCKET_PATH), 0o755)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)          # any local user may connect...
    srv.listen(16)                         # ...but we only honor 3 fixed ops.
    sys.stderr.write("grader daemon listening on %s\n" % SOCKET_PATH)
    sys.stderr.flush()

    while True:
        try:
            conn, _ = srv.accept()
        except InterruptedError:
            continue
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    if "--daemon" in sys.argv:
        serve()
    elif "--selftest" in sys.argv:
        # Offline sanity check of the grading logic against the current /tmp.
        print(json.dumps(op_grademe({}), indent=2))
    else:
        sys.stderr.write("usage: grader.py --daemon\n")
        sys.exit(2)
