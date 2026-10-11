#!/usr/bin/env python3
"""
HaakLeaks — Multi-Source Secret Scanner
By Adrian Martinez | HAAK Cybersecurity

Usage:
  haakleaks.py --git /path/to/repo
  haakleaks.py --docker image:tag
  haakleaks.py --apk app.apk
  haakleaks.py --binary firmware.bin
  haakleaks.py --config /var/www/
  haakleaks.py --pcap capture.pcap
  haakleaks.py --cloud s3://bucket
  haakleaks.py --all /path/to/target
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from leak_scanner.main import main

if __name__ == "__main__":
    main()
