FROM kasmweb/kali-rolling-desktop:1.18.0-rolling-daily

USER root

# Grant raw-socket capability directly to these binaries so they work at full
# strength (SYN scans, OS detection, packet crafting, ARP/ICMP tooling) no
# matter which user the desktop session actually runs the terminal as —
# sidesteps Kasm's internal user-switching entirely.
RUN apt-get update && apt-get install -y --no-install-recommends libcap2-bin \
 && for bin in nmap tcpdump hping3 arping masscan; do \
      p=$(command -v "$bin" || true); \
      [ -n "$p" ] && setcap cap_net_raw,cap_net_admin+eip "$p" || true; \
    done \
 && rm -rf /var/lib/apt/lists/*
