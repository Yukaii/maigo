# Multi-stage Dockerfile for GoReleaser
FROM alpine:latest as certs
RUN apk --update add ca-certificates

FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY maigo /maigo

# Expose port (default for Maigo server)
EXPOSE 8080

# Set the entrypoint
ENTRYPOINT ["/maigo"]
CMD ["server"]
