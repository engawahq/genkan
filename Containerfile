# Genkan's image: one static binary and Mozilla's CA bundle (for upstream identity providers); no
# shell, no package manager. kube-apiserver is trusted through the service
# account's CA only. Runs as a non-root user.
# Built by scripts/build-image.sh.
FROM scratch
COPY --chmod=0555 genkan /genkan
# Modes come from the build context (directories 0755, bundle 0444); see build-image.sh.
COPY etc /etc
USER 65532:65532
ENTRYPOINT ["/genkan"]
