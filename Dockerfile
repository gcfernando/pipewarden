# Multi-stage build that produces a minimal runtime image containing only
# the pipewarden CLI — no build tools, no source code, no pip cache.
#
# Why Alpine?
# python:3.12-slim (Debian-based) carries OS-level CVEs that Alpine does not.
# Alpine's minimal package set gives it a much smaller attack surface, which
# is exactly what we want for a security-focused CLI tool shipped as a container.
#
# Usage — mount your project directory at /work and run:
#
#   docker run --rm \
#     -v "$PWD:/work" \
#     ghcr.io/gcfernando/pipewarden:1.3.0 \
#     --root /work
#
# To scan only secrets (fastest):
#
#   docker run --rm \
#     -v "$PWD:/work" \
#     ghcr.io/gcfernando/pipewarden:1.3.0 \
#     --root /work --only secrets


# =============================================================================
# Stage 1 — Builder
#
# Installs the build toolchain and compiles a wheel from the local source.
# Nothing from this stage leaks into the final image except the .whl file.
# =============================================================================
FROM python:3.12-alpine AS builder

WORKDIR /build

# Copy only the files needed to build the package.
# Copying selectively (instead of COPY . .) avoids invalidating this layer
# when unrelated files like tests or docs change.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src

# Build the wheel. --no-cache-dir keeps the layer small by preventing pip
# from writing its HTTP cache to disk.
RUN pip install --no-cache-dir build \
    && python -m build --wheel


# =============================================================================
# Stage 2 — Runtime
#
# Starts from a clean Alpine base so the final image contains only what is
# needed to run pipewarden — no compiler, no build headers, no source code.
# =============================================================================
FROM python:3.12-alpine

# Install runtime system dependencies:
#   git            — required by pipewarden to list tracked files and to run
#                    gitleaks history scanning (if gitleaks is also installed)
#   ca-certificates — required for pip/gitleaks to make HTTPS connections
#
# --no-cache tells apk not to store the index on disk, keeping the layer small.
# No cleanup step needed — apk --no-cache handles it automatically.
RUN apk add --no-cache \
    git \
    ca-certificates

# Copy the wheel built in the previous stage and install it, then remove
# the wheel file — it is no longer needed once pip has installed it.
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl \
    && rm /tmp/*.whl

# Create a dedicated non-root user to run the tool.
# Running as root inside a container is a security risk — if the container
# is ever compromised, a non-root user limits what an attacker can do.
# UID 1000 matches the default user on most Linux developer workstations,
# which avoids permission issues when writing output files to a mounted volume.
# Alpine uses adduser (not useradd) with -D to skip password prompts.
RUN adduser -D -u 1000 guard

USER guard

# /work is the conventional mount point for the repository being scanned.
# All pipewarden commands default to --root . so mounting here means users
# can omit --root entirely when running the container.
WORKDIR /work

# The entrypoint is the CLI itself. Any arguments passed to docker run are
# forwarded directly to pipewarden (e.g. --root /work --only secrets).
ENTRYPOINT ["pipewarden"]

# Default command shows the help text when the container is run with no
# arguments. This gives users immediate feedback on available options.
CMD ["--help"]
