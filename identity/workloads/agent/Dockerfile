# Optional custom image; the k8s manifests use ghcr.io/spiffe/spire-agent directly.
FROM ghcr.io/spiffe/spire-agent:1.11.2
COPY fetch-svid.sh /usr/local/bin/fetch-svid.sh
RUN chmod +x /usr/local/bin/fetch-svid.sh
ENTRYPOINT ["/usr/local/bin/fetch-svid.sh"]
