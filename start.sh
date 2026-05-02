#!/bin/bash
sudo docker compose up -d
sleep 3
source venv/bin/activate
sudo venv/bin/python3 netwatch.py all
