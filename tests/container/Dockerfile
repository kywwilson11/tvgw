# The gateway of tvgw's container tier (tests/container/README.md): a Debian 13 computer with what the
# package depends on (packaging/nfpm.yaml), booted with systemd as PID 1. tvgw itself is not in the image:
# the tests copy the checkout in, as deploy/sync-install.sh does. Built by .github/workflows/container.yml
# and by tests/container/conftest.py when TVGW_CONTAINER_IMAGE names no image.
#
# The official image's multi-architecture index, read from Docker Hub on 2026-11-03: the same debian:13
# that release.yml installs the package into (tests/unit/test_container_harness.py keeps the two equal).
FROM debian:13@sha256:2dc419c6d7fe3dad0a2f9fd469c34cc90b0f9ba642d8fde837fe3d7d34a0e7f1

ENV container=docker LANG=C.UTF-8
# dumpcap stays 0755 root:root, as install.sh requires (docs/how-it-works/capture.md#what-dumpcap-needs). The list is
# nfpm.yaml's depends and recommends, then what a computer has that the slim image lacks: udev, which
# NetworkManager needs before it manages a port, and D-Bus, which nmcli talks over. After them, the
# tests' own tools: busybox (the TV's DHCP client) and rsync (the copy of the checkout).
RUN echo 'wireshark-common wireshark-common/install-setuid boolean false' | debconf-set-selections \
	&& apt-get update \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
		python3 python3-venv nftables iproute2 procps kmod util-linux network-manager dnsmasq nginx \
		libnginx-mod-stream tcpdump conntrack tshark wireshark-common curl ca-certificates systemd \
		logrotate \
		systemd-sysv udev dbus \
		busybox rsync \
	&& rm -rf /var/lib/apt/lists/*
COPY image/ /
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
