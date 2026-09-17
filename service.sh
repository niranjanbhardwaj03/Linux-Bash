#!/bin/bash

# ============================================================
# Linux Service Monitor & Auto-Restart Script
# ============================================================
echo 
echo   "        Written By: NIRANJAN BHARDWAJ......  "
echo 
SERVICES=(
    "haproxy"
    "keepalived"
    "patroni"
    "etcd"
    "postgresql"
    "pgbouncer"
    "ssh"
)

LOG_FILE="/var/log/service_monitor.log"

echo
echo "============================================================"
echo "        SERVICE MONITOR & AUTO-RESTART"
echo "============================================================"
echo "Hostname : $(hostname)"
echo "Date     : $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo

# ------------------------------------------------------------
# Check root permission
# ------------------------------------------------------------

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run this script as root."
    echo "        sudo $0"
    exit 1
fi

# ------------------------------------------------------------
# Check each service
# ------------------------------------------------------------

for SERVICE in "${SERVICES[@]}"; do

    echo "------------------------------------------------------------"
    echo "Checking service: $SERVICE"
    echo "------------------------------------------------------------"

    # --------------------------------------------------------
    # 1. Check whether service exists
    # --------------------------------------------------------

    if ! systemctl list-unit-files --type=service \
        | grep -q "^${SERVICE}.service"; then

        echo "[SKIP] $SERVICE : Service not present on this machine"
        echo

        continue
    fi

    echo "[FOUND] $SERVICE : Service is present"

    # --------------------------------------------------------
    # 2. Get current service status
    # --------------------------------------------------------

    BEFORE_STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)

    ENABLE_STATUS=$(systemctl is-enabled "$SERVICE" 2>/dev/null)

    echo "[STATUS] Current : $BEFORE_STATUS"
    echo "[STATUS] Enabled : $ENABLE_STATUS"

    # --------------------------------------------------------
    # 3. Service is already running
    # --------------------------------------------------------

    if [ "$BEFORE_STATUS" = "active" ]; then

        echo "[OK] $SERVICE : Service is running good."

        echo "$(date '+%Y-%m-%d %H:%M:%S') [OK] $SERVICE running" \
            >> "$LOG_FILE"

        echo
        continue
    fi

    # --------------------------------------------------------
    # 4. Service is not running
    # --------------------------------------------------------

    echo
    echo "[WARNING] $SERVICE is not running."
    echo "before: $BEFORE_STATUS"

    # --------------------------------------------------------
    # 5. Try to start the service
    # --------------------------------------------------------

    echo "action: Starting $SERVICE..."

    systemctl start "$SERVICE"

    # Give service some time to start
    sleep 3

    # --------------------------------------------------------
    # 6. Check service after start
    # --------------------------------------------------------

    AFTER_STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)

    if [ "$AFTER_STATUS" = "active" ]; then

        echo "now: running"
        echo "[OK] $SERVICE : Service started successfully."

        echo "$(date '+%Y-%m-%d %H:%M:%S') [STARTED] $SERVICE successfully" \
            >> "$LOG_FILE"

    else

        echo "now: NOT RUNNING"
        echo "[FAILED] $SERVICE : Service could not be started."

        echo
        echo "Latest 10 logs/errors for $SERVICE:"
        echo "============================================================"

        journalctl -u "$SERVICE" -n 10 --no-pager

        echo "============================================================"

        echo "$(date '+%Y-%m-%d %H:%M:%S') [FAILED] $SERVICE failed to start" \
            >> "$LOG_FILE"
    fi

    echo

done

echo "============================================================"
echo "                 FINAL SUMMARY"
echo "============================================================"

for SERVICE in "${SERVICES[@]}"; do

    # Check service exists
    if ! systemctl list-unit-files --type=service \
        | grep -q "^${SERVICE}.service"; then

        echo "[NOT PRESENT] $SERVICE"
        continue
    fi

    STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)

    if [ "$STATUS" = "active" ]; then
        echo "[GOOD]        $SERVICE : Running"
    else
        echo "[PROBLEM]     $SERVICE : $STATUS"
    fi

done

echo "============================================================"
echo "Monitoring completed: $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
