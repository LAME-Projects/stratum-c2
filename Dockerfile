# =============================================================================
# Stratum C2 — Dockerfile (single-stage)
#
# Contains the full toolchain needed to compile agents at deploy time:
# Python server + Rust (rustup) + clang/lld (MSVC cross) + xwin Windows SDK.
#
# Agents are compiled on-demand by the deploy wizard — each deployment
# produces artifacts with unique folder names, provider config, and keys.
# Pre-compiled binaries are not meaningful here.
#
# USAGE:
#   docker build -t stratum-c2 .
#   docker run --rm -it \
#     -v ./server.yml:/app/server.yml:ro \
#     -v ./sessions:/app/sessions \
#     -v ./logs:/app/logs \
#     -v ./keys:/app/keys \
#     -v ./certs:/app/certs \
#     -v ./credentials:/app/credentials \
#     -v ./deployments:/app/deployments \
#     -p 7443:7443 \
#     stratum-c2
#
# IMAGE SIZE: ~4 GB (rustup + clang/llvm/lld + xwin SDK ~600 MB + Python deps)
# BUILD TIME: ~20 min first build (xwin SDK download + index); cached after that.
# =============================================================================

FROM python:3.12-slim-bookworm

# ── System dependencies ───────────────────────────────────────────────────────
# Separate layer: these rarely change and anchor the cache.
RUN apt-get update && apt-get install -y --no-install-recommends \
        # Rust installer dependencies
        curl \
        # musl toolchain — x86_64-unknown-linux-musl
        musl-tools \
        # LLVM/Clang — clang-cl + lld-link + llvm-lib + llvm-rc for MSVC targets
        clang \
        llvm \
        lld \
        # Build essentials
        pkg-config \
        ca-certificates \
        # xwin needs this to extract Windows SDK cabinet files
        libssl-dev \
        # openssl CLI — used by deploy wizard for RSA + AES operations
        openssl \
    && rm -rf /var/lib/apt/lists/*

# Symlink clang-cl, lld-link, llvm-lib, llvm-rc into PATH.
# Debian packages versioned binaries (e.g. clang-14); we need the bare names.
RUN ln -sf "$(which clang)"    /usr/local/bin/clang-cl  2>/dev/null || true && \
    ln -sf "$(which lld-link)" /usr/local/bin/lld-link  2>/dev/null || true && \
    ln -sf "$(which llvm-lib)" /usr/local/bin/llvm-lib  2>/dev/null || true && \
    ln -sf "$(which llvm-rc)"  /usr/local/bin/llvm-rc   2>/dev/null || true && \
    for tool in clang-cl lld-link llvm-lib llvm-rc; do \
      if ! command -v $tool >/dev/null 2>&1; then \
        versioned=$(ls /usr/bin/${tool}-* 2>/dev/null | sort -V | tail -1); \
        [ -n "$versioned" ] && ln -sf "$versioned" /usr/local/bin/$tool; \
      fi; \
    done

# ── Rust toolchain ────────────────────────────────────────────────────────────
# Separate layer: pinned rustup install + targets. Changes infrequently.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --profile minimal && \
    rustup target add \
        x86_64-unknown-linux-musl \
        x86_64-pc-windows-msvc \
        x86_64-unknown-none

# ── cargo xwin + Windows SDK ──────────────────────────────────────────────────
# Heaviest layer (~600 MB download). Cached as long as xwin version is unchanged.
# Runs as root so the SDK lands in /root/.xwin — readable by all users.
RUN cargo install xwin --version 0.6.5 --locked && \
    xwin --accept-license splat --output /root/.xwin

# ── MSVC cross-compilation environment ───────────────────────────────────────
# These env vars are picked up by cargo when building windows-msvc targets.
ENV CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER=lld-link \
    CC_x86_64_pc_windows_msvc=clang-cl \
    CXX_x86_64_pc_windows_msvc=clang-cl \
    AR_x86_64_pc_windows_msvc=llvm-lib \
    RC=llvm-rc \
    CFLAGS_x86_64_pc_windows_msvc="\
        -Wno-unused-command-line-argument \
        -fuse-ld=lld-link \
        /imsvc/root/.xwin/crt/include \
        /imsvc/root/.xwin/sdk/include/ucrt \
        /imsvc/root/.xwin/sdk/include/um \
        /imsvc/root/.xwin/sdk/include/shared" \
    RUSTFLAGS="\
        -L/root/.xwin/crt/lib/x86_64 \
        -L/root/.xwin/sdk/lib/um/x86_64 \
        -L/root/.xwin/sdk/lib/ucrt/x86_64"

# ── Python dependencies ───────────────────────────────────────────────────────
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ── Application source ────────────────────────────────────────────────────────
# Copied last so source changes don't invalidate the toolchain layers above.
COPY stratum-server.py .
COPY server/    server/
COPY core/      core/
COPY providers/ providers/
COPY agents/    agents/
COPY webui/     webui/

# ── Runtime directories ───────────────────────────────────────────────────────
# Created here so the container starts cleanly even without volume mounts.
# In production all of these should be bind-mounted from the host.
RUN mkdir -p sessions logs keys certs credentials deployments downloads

# ── Security: drop to non-root ────────────────────────────────────────────────
# cargo/rustup are in /usr/local/{cargo,rustup} — world-readable, so the
# stratum user can invoke cargo at deploy time without sudo.
RUN useradd --system --no-create-home --shell /sbin/nologin stratum && \
    chown -R stratum:stratum /app && \
    chmod -R o+rX /usr/local/cargo /usr/local/rustup /root/.xwin
USER stratum

EXPOSE 7443

ENTRYPOINT ["python3", "stratum-server.py"]
