#!/usr/bin/env bash
set -u

LOGDIR=/tmp/iot-gateways
mkdir -p "$LOGDIR"

# Sanity: make sure master.key already exists. Three processes racing to
# create it would each generate a different key and the whole pipeline breaks.
if [ ! -f ~/iot-pipeline/gateway/master.key ]; then
  echo "ERROR: master.key missing. Start gateway.py once manually first."
  exit 1
fi

cd ~/iot-pipeline/gateway

# Each gateway: own bind address, own type, own log file.
GATEWAY_BIND=aaaa::1 GATEWAY_TYPE=temp  \
  nohup python3 gateway.py > "$LOGDIR/gateway-temp.log"  2>&1 &
echo "gateway_temp  PID $!"

GATEWAY_BIND=bbbb::1 GATEWAY_TYPE=hum   \
  nohup python3 gateway.py > "$LOGDIR/gateway-hum.log"   2>&1 &
echo "gateway_hum   PID $!"

GATEWAY_BIND=cccc::1 GATEWAY_TYPE=press \
  nohup python3 gateway.py > "$LOGDIR/gateway-press.log" 2>&1 &
echo "gateway_press PID $!"

sleep 1
echo
echo "Three gateways running. Logs:"
ls -la "$LOGDIR"/gateway-*.log
echo
echo "Stop: ~/iot-pipeline/gateway/stop_gateways.sh"