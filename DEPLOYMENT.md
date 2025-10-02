# Maigo Deployment Guide

This guide covers deploying Maigo in production using Docker.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Production Deployment](#production-deployment)
- [Environment Configuration](#environment-configuration)
- [Database Management](#database-management)
- [Monitoring & Logging](#monitoring--logging)
- [Backup & Recovery](#backup--recovery)
- [Security Best Practices](#security-best-practices)

## Prerequisites

- Docker 20.10+
- Docker Compose 2.0+
- At least 1GB RAM
- PostgreSQL-compatible database (or use included Docker service)

## Quick Start

### 1. Clone and Configure

```bash
# Clone the repository
git clone https://github.com/yukaii/maigo.git
cd maigo

# Copy environment template
cp .env.production.example .env.production

# Edit configuration
vim .env.production
```

### 2. Generate Secrets

```bash
# Generate JWT secret (minimum 32 characters)
openssl rand -hex 32

# Generate database password
openssl rand -base64 32

# Generate Redis password
openssl rand -base64 32
```

### 3. Start Services

```bash
# Start all services
docker-compose --env-file .env.production up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f maigo
```

### 4. Verify Deployment

```bash
# Health check
curl http://localhost:8080/health

# Expected response:
# {"status":"ok","service":"maigo","message":"Server is healthy and running"}
```

## Production Deployment

### Build Production Image

```bash
# Build the production Docker image
docker build -f Dockerfile.production -t maigo:latest .

# Tag for registry
docker tag maigo:latest your-registry.com/maigo:latest

# Push to registry
docker push your-registry.com/maigo:latest
```

### Docker Compose Production Setup

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  maigo:
    image: your-registry.com/maigo:latest
    restart: always
    env_file:
      - .env.production
    ports:
      - "8080:8080"
    depends_on:
      - postgres
    volumes:
      - ./logs:/app/logs
    networks:
      - maigo-network

  postgres:
    image: postgres:16-alpine
    restart: always
    env_file:
      - .env.production
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./backups:/backups
    networks:
      - maigo-network

volumes:
  postgres_data:

networks:
  maigo-network:
    driver: bridge
```

Start production stack:

```bash
docker-compose -f docker-compose.prod.yml --env-file .env.production up -d
```

## Environment Configuration

### Production Environment (.env.production)

```bash
# Database
DB_NAME=maigo
DB_USER=maigo
DB_PASSWORD=<secure-password>
DB_PORT=5432

# Server
PORT=8080
HOST=0.0.0.0

# OAuth & Security
JWT_SECRET=<32-char-minimum-secret>
OAUTH2_CLIENT_ID=maigo-cli
OAUTH2_CLIENT_SECRET=<secure-secret>

# Application
GIN_MODE=release
LOG_LEVEL=info
LOG_FORMAT=json

# Feature Flags
SHORT_CODE_LENGTH=6
```

### Staging Environment (.env.staging)

Similar to production but with:
- Different database
- Debug logging enabled
- Lower resource limits

### Development Environment (.env.development)

```bash
GIN_MODE=debug
LOG_LEVEL=debug
LOG_FORMAT=text
```

## Database Management

### Migrations

Migrations run automatically on startup. To run manually:

```bash
# Inside container
docker-compose exec maigo /app/maigo migrate up

# Roll back
docker-compose exec maigo /app/maigo migrate down
```

### Database Backup

```bash
# Create backup
docker-compose exec postgres pg_dump -U maigo maigo > backup_$(date +%Y%m%d_%H%M%S).sql

# Automated backup (add to crontab)
0 2 * * * docker-compose exec postgres pg_dump -U maigo maigo | gzip > /backups/maigo_$(date +\%Y\%m\%d).sql.gz
```

### Database Restore

```bash
# Restore from backup
docker-compose exec -T postgres psql -U maigo maigo < backup.sql

# Or from gzipped backup
gunzip -c backup.sql.gz | docker-compose exec -T postgres psql -U maigo maigo
```

## Monitoring & Logging

### View Logs

```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f maigo

# Last 100 lines
docker-compose logs --tail=100 maigo
```

### Structured JSON Logs

In production mode, logs are output in JSON format:

```json
{
  "time": "2025-10-02T10:30:00Z",
  "level": "INFO",
  "msg": "HTTP request",
  "method": "POST",
  "path": "/api/v1/urls",
  "status": 201,
  "latency": "15.2ms",
  "client_ip": "192.168.1.1"
}
```

### Health Monitoring

```bash
# Application health
curl http://localhost:8080/health

# Readiness check (includes database)
curl http://localhost:8080/health/ready

# Docker health status
docker ps --format "table {{.Names}}\t{{.Status}}"
```

## Backup & Recovery

### Automated Backup Script

Create `scripts/backup.sh`:

```bash
#!/bin/bash
BACKUP_DIR="/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Backup database
docker-compose exec -T postgres pg_dump -U maigo maigo | gzip > "$BACKUP_DIR/maigo_$DATE.sql.gz"

# Backup configuration
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" config/ .env.production

# Keep only last 30 days
find "$BACKUP_DIR" -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

Make executable:

```bash
chmod +x scripts/backup.sh
```

Add to crontab:

```bash
0 2 * * * /path/to/maigo/scripts/backup.sh >> /var/log/maigo-backup.log 2>&1
```

### Disaster Recovery

1. **Stop services:**
   ```bash
   docker-compose down
   ```

2. **Restore database:**
   ```bash
   gunzip -c backup.sql.gz | docker-compose exec -T postgres psql -U maigo maigo
   ```

3. **Restore configuration:**
   ```bash
   tar -xzf config_backup.tar.gz
   ```

4. **Restart services:**
   ```bash
   docker-compose up -d
   ```

## Security Best Practices

### 1. Secrets Management

- ✅ Never commit secrets to version control
- ✅ Use strong passwords (minimum 32 characters)
- ✅ Rotate secrets regularly
- ✅ Use environment variables or secret management tools

### 2. Network Security

```yaml
# Use internal networks
networks:
  maigo-network:
    driver: bridge
    internal: false  # Set to true to isolate from internet
```

### 3. SSL/TLS

Use a reverse proxy (nginx/caddy) for SSL termination:

```nginx
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 4. Database Security

```bash
# Enable SSL for PostgreSQL
DB_SSL_MODE=require

# Use connection pooling limits
MAX_CONNECTIONS=25
MIN_CONNECTIONS=5
```

### 5. Container Security

- Run as non-root user (already configured)
- Use minimal base images (Alpine)
- Scan images for vulnerabilities:
  ```bash
  docker scan maigo:latest
  ```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs maigo

# Verify environment variables
docker-compose config

# Check resource usage
docker stats
```

### Database Connection Issues

```bash
# Test database connectivity
docker-compose exec maigo wget -qO- http://localhost:8080/health/ready

# Check PostgreSQL logs
docker-compose logs postgres

# Verify credentials
docker-compose exec postgres psql -U maigo -d maigo -c "SELECT 1"
```

### Performance Issues

```bash
# Monitor resource usage
docker stats

# Check connection pool
docker-compose logs maigo | grep "connection pool"

# Increase resources if needed
docker-compose up -d --scale maigo=2
```

## Scaling

### Horizontal Scaling

```bash
# Scale to 3 instances
docker-compose up -d --scale maigo=3
```

Use a load balancer (nginx/HAProxy) to distribute traffic.

### Vertical Scaling

Update `docker-compose.yml`:

```yaml
services:
  maigo:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 2G
        reservations:
          cpus: '1'
          memory: 1G
```

## Production Checklist

- [ ] Generate secure secrets
- [ ] Configure environment variables
- [ ] Set up SSL/TLS termination
- [ ] Configure firewall rules
- [ ] Set up automated backups
- [ ] Configure log rotation
- [ ] Set up monitoring/alerting
- [ ] Test disaster recovery
- [ ] Document runbooks
- [ ] Set up CI/CD pipeline

## Support

For issues and questions:
- GitHub Issues: https://github.com/yukaii/maigo/issues
- Documentation: https://github.com/yukaii/maigo/blob/main/README.md
