# 🐳 Cyberdome Sentinel Docker Deployment

This guide explains how to deploy Cyberdome Sentinel using Docker and Docker Compose on Linux machines.

## 📋 Prerequisites

- **Docker** (version 20.10 or higher)
- **Docker Compose** (version 2.0 or higher)
- **Linux** (Ubuntu 20.04+, CentOS 8+, or similar)
- **Git** (for cloning the repository)

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone <your-repo-url>
cd FileScannerCyberDome
```

### 2. Make Scripts Executable
```bash
chmod +x start-docker.sh stop-docker.sh
```

### 3. Start the Application
```bash
# Simple deployment (Flask only)
./start-docker.sh

# Full stack deployment (with Redis and Nginx)
./start-docker.sh --full
```

### 4. Access the Application
Open your browser and navigate to: **http://localhost:5000**

## 🏗️ Deployment Options

### Option 1: Simple Stack (Recommended for Development)
- **Flask Application** only
- **Port 5000** exposed
- **Persistent data** stored in host directories
- **Easy to manage** and debug

```bash
./start-docker.sh
```

### Option 2: Full Stack (Recommended for Production)
- **Flask Application** with Redis caching
- **Nginx** reverse proxy on ports 80/443
- **Redis** for session management
- **Load balancing** and SSL support ready

```bash
./start-docker.sh --full
```

## 📁 Directory Structure

After deployment, the following directories will be created:

```
FileScannerCyberDome/
├── data/                 # Database files
├── uploads/             # Uploaded files
├── yara-rules/          # YARA rule files
├── static/              # Static assets (logo, CSS, JS)
├── logs/                # Application logs
└── docker-compose.yml   # Docker Compose configuration
```

## ⚙️ Configuration

### Environment Variables
Copy `env.production` to `.env` and modify as needed:

```bash
cp env.production .env
nano .env
```

### Key Configuration Options
- **HOST**: Bind address (0.0.0.0 for all interfaces)
- **PORT**: Application port (5000)
- **MAX_CONTENT_LENGTH**: Maximum file upload size (100MB default)
- **SECRET_KEY**: Flask secret key (change in production!)

## 🔧 Management Commands

### View Logs
```bash
# All services
docker-compose logs -f

# Specific service
docker-compose logs -f cyberdome-sentinel
```

### Stop the Application
```bash
# Stop services
./stop-docker.sh

# Stop and clean up
./stop-docker.sh --clean
```

### Restart Services
```bash
docker-compose restart cyberdome-sentinel
```

### Update Application
```bash
docker-compose pull
docker-compose up -d --build
```

## 🔒 Security Considerations

### Production Deployment
1. **Change SECRET_KEY** in environment variables
2. **Use HTTPS** with proper SSL certificates
3. **Configure firewall** to limit access
4. **Regular updates** of base images
5. **Monitor logs** for suspicious activity

### Network Security
- **Internal network** (172.20.0.0/16) for container communication
- **Port exposure** limited to necessary services
- **Health checks** for service monitoring

## 📊 Monitoring and Health Checks

### Health Check Endpoints
- **Application**: `http://localhost:5000/`
- **Docker Health**: Built-in health checks for all services

### Log Monitoring
```bash
# Real-time log monitoring
docker-compose logs -f --tail=100

# Export logs for analysis
docker-compose logs > cyberdome-logs.txt
```

## 🐛 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using port 5000
sudo netstat -tlnp | grep :5000

# Kill the process or change port in docker-compose.yml
```

#### Permission Denied
```bash
# Fix directory permissions
sudo chown -R $USER:$USER data uploads yara-rules static logs
chmod 755 data uploads yara-rules static logs
```

#### Container Won't Start
```bash
# Check container logs
docker-compose logs cyberdome-sentinel

# Check container status
docker-compose ps
```

#### Database Issues
```bash
# Reset database (WARNING: This will delete all data!)
docker-compose down
rm -rf data/*
docker-compose up -d
```

### Debug Mode
For debugging, modify `docker-compose.yml`:

```yaml
environment:
  - DEBUG=true
  - FLASK_ENV=development
```

## 🔄 Backup and Recovery

### Backup Data
```bash
# Create backup directory
mkdir -p backups/$(date +%Y%m%d)

# Backup important directories
cp -r data backups/$(date +%Y%m%d)/
cp -r uploads backups/$(date +%Y%m%d)/
cp -r yara-rules backups/$(date +%Y%m%d)/
```

### Restore Data
```bash
# Stop services
./stop-docker.sh

# Restore from backup
cp -r backups/20241220/data ./
cp -r backups/20241220/uploads ./
cp -r backups/20241220/yara-rules ./

# Start services
./start-docker.sh
```

## 📈 Scaling

### Horizontal Scaling
```bash
# Scale Flask application
docker-compose up -d --scale cyberdome-sentinel=3
```

### Load Balancer
Use the full stack with Nginx for load balancing multiple Flask instances.

## 🆘 Support

### Getting Help
1. Check the logs: `docker-compose logs -f`
2. Verify configuration: `docker-compose config`
3. Check container status: `docker-compose ps`
4. Review this documentation

### Useful Commands
```bash
# System information
docker system df
docker system info

# Container statistics
docker stats

# Resource usage
docker system prune -a
```

## 📝 License

This Docker deployment configuration is part of the Cyberdome Sentinel project.
