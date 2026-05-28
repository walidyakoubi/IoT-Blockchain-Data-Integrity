#!/usr/bin/env bash
pkill -f "python3 gateway.py" || true
sleep 1
remaining=$(pgrep -f "python3 gateway.py" || true)
if [ -n "$remaining" ]; then
  echo "Some gateways still running, force-killing: $remaining"
  pkill -9 -f "python3 gateway.py"
fi
echo "All gateways stopped."