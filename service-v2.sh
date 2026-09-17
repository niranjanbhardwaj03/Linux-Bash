#!/bin/bash

# ============================================================
# Linux Service Monitor + Auto Restart + Telegram Alert
# ============================================================

# -----------------------------
# Services to monitor
# -----------------------------

SERVICES=(
    "haproxy"
    "keepalived"
    "patroni"
    "etcd"
    "postgresql"
    "pgbouncer"
    "ssh"
)

# -----------------------------
# Telegram Configuration
# -----------------------------

#TELEGRAM_BOT_TOKEN="8773928069:AAGRPc4PQ-ICVlXqUp9KiUdh2Ac8sr3kUfw"
#TELEGRAM_CHAT_ID="6026618693"

# -----------------------------
# Log file
# -----------------------------

LOG_FILE="/var/log/service_monitor.log"


# ============================================================
# Telegram Function
# ============================================================

send_telegram()
{
    local MESSAGE="$1"

    curl -s -X POST \
        "https://api.telegram.org/bot8773928069:AAGRPc4PQ-ICVlXqUp9KiUdh2Ac8sr3kUfw$/sendMessage" \
        -d chat_id="6026618693" \
        --data-urlencode text="$MESSAGE" \
        > /dev/null
}


# ============================================================
# Log Function
# ============================================================

write_log()
{
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG_FILE"
}


# ============================================================
# Check Root
# ============================================================

if [ "$EUID" -ne 0 ]; then

    echo "[ERROR] Please run this script as root."

    exit 1

fi


# ============================================================
# Header
# ============================================================

echo
echo "============================================================"
echo "       SERVICE MONITOR + AUTO RESTART"
echo "============================================================"
echo "Hostname : $(hostname)"
echo "Date     : $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"
echo


# ============================================================
# Monitor Services
# ============================================================

for SERVICE in "${SERVICES[@]}"; do

    echo "------------------------------------------------------------"
    echo "Checking: $SERVICE"
    echo "------------------------------------------------------------"


    # --------------------------------------------------------
    # Check whether service exists
    # --------------------------------------------------------

    if ! systemctl list-unit-files --type=service \
        | grep -q "^${SERVICE}.service"; then

        echo "[SKIP] $SERVICE : Service not present"

        write_log "[SKIP] $SERVICE : Service not present"

        echo

        continue
    fi


    echo "[FOUND] $SERVICE : Service is present"


    # --------------------------------------------------------
    # Check current status
    # --------------------------------------------------------

    BEFORE_STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)

    ENABLE_STATUS=$(systemctl is-enabled "$SERVICE" 2>/dev/null)

    echo "[STATUS] Current : $BEFORE_STATUS"
    echo "[STATUS] Enabled : $ENABLE_STATUS"


    # --------------------------------------------------------
    # Service is running
    # --------------------------------------------------------

    if [ "$BEFORE_STATUS" = "active" ]; then

        echo "[OK] $SERVICE : Service is running good."

        write_log "[OK] $SERVICE : Running"

        echo

        continue

    fi


    # --------------------------------------------------------
    # Service is DOWN
    # --------------------------------------------------------

    echo
    echo "[WARNING] $SERVICE is not running."
    echo "before: $BEFORE_STATUS"


    # --------------------------------------------------------
    # Telegram DOWN Alert
    # --------------------------------------------------------

    DOWN_MESSAGE="🚨 SERVICE DOWN

Server: $(hostname)
Service: $SERVICE

Before: $BEFORE_STATUS
Enabled: $ENABLE_STATUS

Action: Starting service..."

    send_telegram "$DOWN_MESSAGE"


    # --------------------------------------------------------
    # Start Service
    # --------------------------------------------------------

    echo "action: Starting $SERVICE..."

    write_log "[ACTION] Starting $SERVICE"

    systemctl start "$SERVICE"

    sleep 3


    # --------------------------------------------------------
    # Check after START
    # --------------------------------------------------------

    AFTER_STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)


    if [ "$AFTER_STATUS" = "active" ]; then

        echo "now: running"

        echo "[OK] $SERVICE : Service started successfully."

        write_log "[SUCCESS] $SERVICE started successfully"


        SUCCESS_MESSAGE="✅ SERVICE RECOVERED

Server: $(hostname)
Service: $SERVICE

Before: $BEFORE_STATUS
Action: START
Now: RUNNING

Time: $(date '+%Y-%m-%d %H:%M:%S')"

        send_telegram "$SUCCESS_MESSAGE"


    else

        # ----------------------------------------------------
        # START failed
        # ----------------------------------------------------

        echo "now: NOT RUNNING"

        echo "[FAILED] $SERVICE : Start failed."

        write_log "[FAILED] $SERVICE : Start failed"


        echo
        echo "Trying restart..."

        write_log "[ACTION] Restarting $SERVICE"

        systemctl restart "$SERVICE"

        sleep 3


        # ----------------------------------------------------
        # Check after RESTART
        # ----------------------------------------------------

        FINAL_STATUS=$(systemctl is-active "$SERVICE" 2>/dev/null)


        if [ "$FINAL_STATUS" = "active" ]; then

            echo "now: running"

            echo "[OK] $SERVICE : Restart successful."

            write_log "[SUCCESS] $SERVICE restarted successfully"


            RESTART_MESSAGE="✅ SERVICE RECOVERED

Server: $(hostname)
Service: $SERVICE

Before: $BEFORE_STATUS
Action: START → RESTART
Now: RUNNING

Time: $(date '+%Y-%m-%d %H:%M:%S')"

            send_telegram "$RESTART_MESSAGE"


        else

            # ------------------------------------------------
            # Service still failed
            # ------------------------------------------------

            echo "now: FAILED"

            echo "[CRITICAL] $SERVICE : Restart failed."

            write_log "[CRITICAL] $SERVICE : Restart failed"


            # ------------------------------------------------
            # Get latest 10 logs
            # ------------------------------------------------

            SERVICE_LOGS=$(journalctl \
                -u "$SERVICE" \
                -n 10 \
                --no-pager \
                2>&1)


            echo
            echo "Latest 10 logs:"
            echo "============================================================"

            echo "$SERVICE_LOGS"

            echo "============================================================"


            # ------------------------------------------------
            # Send Telegram Critical Alert
            # ------------------------------------------------

            CRITICAL_MESSAGE="🔴 CRITICAL SERVICE FAILURE

Server: $(hostname)
Service: $SERVICE

Before: $BEFORE_STATUS
Action: START → RESTART
Now: FAILED

Latest 10 logs:

$SERVICE_LOGS"

            send_telegram "$CRITICAL_MESSAGE"

        fi

    fi

    echo

done


# ============================================================
# Final Summary
# ============================================================

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
