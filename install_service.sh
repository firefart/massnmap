#!/bin/sh

echo "Copying unit file"
cp /home/massnmap/massnmap.service /etc/systemd/system/massnmap.service
cp /home/massnmap/massnmap.timer /etc/systemd/system/massnmap.timer
echo "reloading systemctl"
systemctl daemon-reload
echo "enabling service"
systemctl enable massnmap.timer
systemctl start massnmap.timer
systemctl status massnmap.service
systemctl status massnmap.timer
systemctl list-timers --all
