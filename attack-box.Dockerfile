FROM kasmweb/kali-rolling-desktop:1.18.0-rolling-daily

USER root

# Grant raw-socket capability directly to these binaries so they work at full
# strength (SYN scans, OS detection, packet crafting, ARP/ICMP tooling) no
# matter which user the desktop session actually runs the terminal as —
# sidesteps Kasm's internal user-switching entirely.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin sudo \
 && for bin in nmap tcpdump hping3 arping masscan; do \
      p=$(command -v "$bin" || true); \
      [ -n "$p" ] && setcap cap_net_raw,cap_net_admin+eip "$p" || true; \
    done \
 && rm -rf /var/lib/apt/lists/*

# All the targets on the vulnbench network (DVWA, Juice Shop, Mutillidae,
# etc.) are plain HTTP — no TLS at all. Firefox's HTTPS-Only Mode auto-
# upgrades every http:// navigation to https:// first, so without this every
# target throws "SSL received a record that exceeded the maximum permissible
# length" (a TLS client hitting a plain-HTTP server). This is a real Mozilla
# enterprise policy (not a preference override), applied system-wide
# regardless of which Firefox profile a session ends up using.
RUN set -eux; \
    FIREFOX_BIN="$(command -v firefox || command -v firefox-esr)"; \
    FIREFOX_DIR="$(dirname "$(readlink -f "$FIREFOX_BIN")")"; \
    mkdir -p "$FIREFOX_DIR/distribution"; \
    printf '%s' '{"policies":{"HttpsOnlyMode":"disabled"}}' > "$FIREFOX_DIR/distribution/policies.json"

# Give kasm-user real sudo access. The base image runs the desktop session
# as this user but never configures sudo for it at all — no sudoers entry
# and no password hash — so `sudo <anything>` in the terminal just sits at
# an unsatisfiable password prompt. setcap above only covers a fixed list
# of raw-socket binaries; this is the general fallback for anything else
# that needs root (apt install, other tools dropped into /opt/tools, etc).
# NOPASSWD since there's no separate account password to type anyway, and
# reaching this terminal at all already required the VNC_PW gate.
RUN echo "kasm-user ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/kasm-user \
 && chmod 0440 /etc/sudoers.d/kasm-user

# Switch back to the image's own non-root user for runtime. Without this,
# `USER root` above becomes the image's baked-in default user — independent
# of whatever docker-compose.yml sets — so the whole desktop session
# (including Firefox) runs as root, which Firefox refuses to do.
USER kasm-user
