#!/bin/bash
# =============================================================
# RabbitMQ Setup Script (HA + QUORUM SAFE for Radius Design)
# =============================================================

set -e

RABBITMQ_USER="radius_user"
RABBITMQ_PASS="radius_pass"
VHOST="radius"
EXCHANGE="radius_exchange"

echo "=============================="
echo " RabbitMQ Radius Setup (HA)"
echo "=============================="

# =============================================================
# 0. CLEAN PREVIOUS SETUP
# =============================================================
echo "[0/6] Cleaning old setup (if exists)..."

rabbitmqctl delete_vhost "$VHOST" 2>/dev/null || true

# =============================================================
# 1. VHOST
# =============================================================
echo "[1/6] Creating vhost..."
rabbitmqctl add_vhost "$VHOST"

# =============================================================
# 2. USER
# =============================================================
echo "[2/6] Creating user..."
rabbitmqctl add_user "$RABBITMQ_USER" "$RABBITMQ_PASS" 2>/dev/null || true
rabbitmqctl set_user_tags "$RABBITMQ_USER" administrator
rabbitmqctl set_permissions -p "$VHOST" "$RABBITMQ_USER" ".*" ".*" ".*"

# =============================================================
# 3. EXCHANGES
# =============================================================
echo "[3/6] Creating exchanges..."

rabbitmqadmin --vhost="$VHOST" \
  --username="$RABBITMQ_USER" --password="$RABBITMQ_PASS" \
  declare exchange --name "$EXCHANGE" --type direct --durable true

# =============================================================
# 4. QUEUES (QUORUM - HA SAFE)
# =============================================================
echo "[4/6] Creating quorum queues..."

declare_quorum_queue () {
  QUEUE_NAME=$1

  rabbitmqadmin --vhost="$VHOST" \
    --username="$RABBITMQ_USER" \
    --password="$RABBITMQ_PASS" \
    declare queue \
    --name "$QUEUE_NAME" \
    --durable true \
    --arguments '{"x-queue-type":"quorum"}'
}

declare_quorum_queue session.start
declare_quorum_queue session.stop
declare_quorum_queue session.stats
declare_quorum_queue sync.session
declare_quorum_queue sync.session.delete

# =============================================================
# 5. BINDINGS
# =============================================================
echo "[5/6] Creating bindings..."

bind_queue () {
  QUEUE=$1
  ROUTING_KEY=$2

  rabbitmqadmin --vhost="$VHOST" \
    --username="$RABBITMQ_USER" --password="$RABBITMQ_PASS" \
    declare binding \
    --source "$EXCHANGE" \
    --destination-type queue \
    --destination "$QUEUE" \
    --routing-key "$ROUTING_KEY"
}

bind_queue session.start session.start
bind_queue session.stop session.stop
bind_queue session.stats session.stats
bind_queue sync.session sync.session
bind_queue sync.session.delete sync.session.delete

# =============================================================
# 6. VERIFY
# =============================================================
echo "[6/6] Verification..."

echo ""
echo "Queues:"
rabbitmqctl list_queues -p "$VHOST" name type durable messages consumers

echo ""
echo "Bindings:"
rabbitmqctl list_bindings -p "$VHOST"

echo ""
echo "DONE - HA READY SETUP COMPLETE"