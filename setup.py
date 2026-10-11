"""
HaakLeaks — setup.py
"""
from setuptools import setup, find_packages

with open("requirements.txt") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name             = "haakleaks",
    version          = "1.0.0",
    description      = "Multi-Source Secret Scanner — git, docker, APK, binary, config, PCAP, cloud",
    long_description = open("README.md").read() if __import__("os").path.isfile("README.md") else "",
    long_description_content_type = "text/markdown",
    author           = "Adrian Martinez",
    author_email     = "me@adrianmartinez.lat",
    url              = "https://github.com/Bl4ckSkul1/haakleaks",
    license          = "MIT",
    packages         = find_packages(exclude=["tests*"]),
    python_requires  = ">=3.10",
    install_requires = requirements,
    entry_points     = {
        "console_scripts": [
            "haakleaks = leak_scanner.main:main",
        ],
    },
    classifiers = [
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
    ],
    keywords = "security secrets-scanning pentest appsec credentials leaks",
    project_urls = {
        "Bug Tracker": "https://github.com/Bl4ckSkul1/haakleaks/issues",
        "Source Code":  "https://github.com/Bl4ckSkul1/haakleaks",
    },
)
