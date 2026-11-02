# =============================================================================
# jhead autonomous-fuzzing RL environment
#
# A single image containing:
#   * the pinned vulnerable source (jhead 3.04) at /src   [model builds this]
#   * AFL++ + clang + AddressSanitizer                    [the fuzzing toolchain]
#   * the MCP server (stdio)                              [runs as user `mcp`]
#   * the privileged grader daemon + ground truth         [runs as root]
#
# Build:  docker build -t jhead-fuzz-env .
# Run:    docker run -i --rm jhead-fuzz-env     (speaks MCP over stdio)
#
# Everything below the build stage works OFFLINE at run time: the source,
# toolchain, reference build and seed are all baked in.
# =============================================================================
FROM aflplusplus/aflplusplus:latest

ENV DEBIAN_FRONTEND=noninteractive

# --- OS packages ------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv git ca-certificates util-linux file \
    && rm -rf /var/lib/apt/lists/*

# --- Python venv for the MCP server (only the MCP server needs pip deps) -----
RUN python3 -m venv /opt/venv
COPY mcp_server/requirements.txt /tmp/requirements.txt
RUN /opt/venv/bin/pip install --no-cache-dir -U pip \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt

# --- Pinned vulnerable source: jhead 3.04 -----------------------------------
# Heap out-of-bounds read in EXIF parsing (process_EXIF, exif.c), reachable by
# feeding a crafted JPEG. This commit predates the upstream fuzz-test fixes.
ARG JHEAD_COMMIT=afadc77764641f2fa415589297a7a0a259566841
RUN git clone https://github.com/Matthias-Wandel/jhead.git /tmp/jhead \
    && git -C /tmp/jhead checkout -q ${JHEAD_COMMIT}

# Model-visible source at /src (read-only: root-owned, no giveaways left here).
RUN mkdir -p /src \
    && cp /tmp/jhead/*.c /tmp/jhead/*.h /tmp/jhead/makefile /src/ \
    && chown -R root:root /src \
    && chmod -R a+rX,go-w /src

# --- Ground truth (root-only) -----------------------------------------------
# A pristine copy of the pinned source + our OWN clean AddressSanitizer build.
# grademe() replays the model's PoC against this reference build to prove the
# crash is a real memory-safety bug in the target, independent of whatever the
# model dropped at /tmp/target.
RUN mkdir -p /opt/grader \
    && cp -r /tmp/jhead /opt/grader/src \
    && clang -g -O1 -fsanitize=address -fno-omit-frame-pointer -w \
        -o /opt/grader/jhead_ref_asan \
        /opt/grader/src/jhead.c /opt/grader/src/jpgfile.c \
        /opt/grader/src/jpgqguess.c /opt/grader/src/paths.c \
        /opt/grader/src/exif.c /opt/grader/src/iptc.c \
        /opt/grader/src/gpsinfo.c /opt/grader/src/makernote.c -lm

# Benign seed used by the grader's behaviour check.
COPY grader/make_seed.py /tmp/make_seed.py
RUN /opt/venv/bin/python /tmp/make_seed.py /opt/grader/seed.jpg

# --- Application code (root-owned, unprivileged users cannot modify it) ------
RUN mkdir -p /app/mcp_server /app/grader
COPY mcp_server/server.py /app/mcp_server/server.py
COPY grader/grader.py     /app/grader/grader.py
COPY entrypoint.sh        /app/entrypoint.sh
RUN chmod 0755 /app/entrypoint.sh

# --- Users ------------------------------------------------------------------
#   root  : grader daemon (privileged)      -- computes the score
#   mcp   : MCP server (unprivileged proxy) -- the model cannot touch it
#   model : runs the model's bash + binaries (unprivileged)
RUN useradd -m -u 1001 -s /bin/bash  model \
    && useradd -m -u 1002 -s /usr/sbin/nologin mcp

# Seed corpus the model starts its AFL campaign from.
RUN mkdir -p /home/model/seeds \
    && /opt/venv/bin/python /tmp/make_seed.py /home/model/seeds/seed.jpg \
    && chown -R model:model /home/model/seeds

# --- Lock down the sensitive trees ------------------------------------------
# Ground truth: root-only, mode 0700. The model cannot read the reference
# build, the pristine source, or anything used to compute the grade.
RUN chown -R root:root /opt/grader /app \
    && chmod 0700 /opt/grader \
    && chmod -R go-rwx /opt/grader \
    && chmod -R go-w /app \
    && rm -rf /tmp/jhead /tmp/make_seed.py /tmp/requirements.txt

# NOTE: we deliberately do NOT set a global ASAN_OPTIONS. AFL++ refuses to fuzz
# when it inherits an ASAN_OPTIONS lacking `symbolize=0`, so a global value would
# break the model's `afl-fuzz`. The grader sets its own ASAN_OPTIONS explicitly
# for every run it performs, so it needs no default here.

# Entrypoint (root): start grader daemon, then drop to `mcp` for the stdio MCP
# server. The container's stdin/stdout ARE the MCP transport.
ENTRYPOINT ["/app/entrypoint.sh"]
