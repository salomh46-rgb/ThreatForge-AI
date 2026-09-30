from typing import Dict, Any

PRESETS: Dict[str, Dict[str, Any]] = {
    "compose_vulnerable_stack": {
        "title": "Docker Compose — Vulnerable Microservices",
        "description": "Production anti-pattern with directly exposed PostgreSQL & Redis ports, plaintext secrets, and unauthenticated internal services.",
        "format": "compose",
        "code": """version: '3.8'

services:
  ingress_proxy:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    depends_on:
      - backend_api

  backend_api:
    image: mycompany/api:v1.2
    environment:
      - DB_HOST=postgres_db
      - DB_PASSWORD=super_insecure_hardcoded_pwd_2026
      - REDIS_HOST=cache_redis
    depends_on:
      - postgres_db
      - cache_redis

  postgres_db:
    image: postgres:15
    ports:
      - "5432:5432" # CRITICAL: Directly exposed to internet!
    environment:
      - POSTGRES_PASSWORD=super_insecure_hardcoded_pwd_2026
      - POSTGRES_DB=production_users

  cache_redis:
    image: redis:7-alpine
    ports:
      - "6379:6379" # CRITICAL: Redis exposed without requirepass or TLS!
"""
    },

    "terraform_aws_ecommerce": {
        "title": "Terraform — AWS E-Commerce Infrastructure",
        "description": "AWS infrastructure featuring public S3 bucket, public RDS instance, and permissive Security Groups (0.0.0.0/0).",
        "format": "terraform",
        "code": """terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

resource "aws_security_group" "web_sg" {
  name        = "web_sg"
  description = "Permissive web ingress"

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "customer_documents" {
  bucket = "prod-customer-private-receipts"
  acl    = "public-read" # CRITICAL: Open S3 Bucket!
}

resource "aws_db_instance" "production_rds" {
  allocated_storage    = 50
  engine               = "postgres"
  instance_class       = "db.t3.medium"
  username             = "admin"
  password             = "HardcodedDbPassword!"
  publicly_accessible = true # CRITICAL: Direct public RDS access!
  storage_encrypted   = false
}

resource "aws_lb" "main_alb" {
  name               = "main-alb"
  internal           = false
  load_balancer_type = "application"
}
"""
    },

    "mermaid_banking_architecture": {
        "title": "Mermaid — Core Banking API Flow",
        "description": "Architectural diagram showing plaintext interservice communication and lack of ingress WAF protection.",
        "format": "mermaid",
        "code": """flowchart TD
    subgraph "Public Internet"
        Attacker["Untrusted Clients / Attacker"]
    end

    subgraph "DMZ / Ingress"
        Gateway["Public API Gateway (Port 80)"]
    end

    subgraph "Private App VPC"
        AuthService["Auth & Identity Service"]
        PaymentWorker["Core Payment Processor"]
    end

    subgraph "Secure Data Tier"
        LedgerDB[("Central Banking Ledger DB")]
        TransactionCache[("Transaction Redis Queue")]
    end

    Attacker -->|Plaintext HTTP:80| Gateway
    Gateway -->|HTTP:8080| AuthService
    Gateway -->|HTTP:8080| PaymentWorker
    PaymentWorker -->|Unencrypted TCP:5432| LedgerDB
    PaymentWorker -->|Plaintext Redis:6379| TransactionCache
"""
    },

    "hardened_zero_trust": {
        "title": "Terraform — Hardened Zero-Trust Defense",
        "description": "Secured enterprise baseline with WAF, private VPC subnets, KMS encryption, and S3 public access block.",
        "format": "terraform",
        "code": """resource "aws_s3_bucket" "secure_assets" {
  bucket = "company-enterprise-vault"
}

resource "aws_s3_bucket_public_access_block" "secure_s3_guard" {
  bucket = aws_s3_bucket.secure_assets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_db_instance" "isolated_rds" {
  allocated_storage    = 100
  engine               = "postgres"
  instance_class       = "db.r6g.large"
  publicly_accessible = false
  storage_encrypted   = true
}

resource "aws_security_group" "private_db_sg" {
  name = "db_isolated_sg"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["10.0.2.0/24"]
  }
}
"""
    }
}
