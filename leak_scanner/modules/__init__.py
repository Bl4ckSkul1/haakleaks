from .git_scanner import GitScanner
from .docker_scanner import DockerScanner
from .apk_scanner import APKScanner
from .binary_scanner import BinaryScanner
from .config_scanner import ConfigScanner
from .pcap_scanner import PCAPScanner
from .cloud_scanner import CloudScanner

ALL_SCANNERS = {
    "git":    GitScanner,
    "docker": DockerScanner,
    "apk":    APKScanner,
    "binary": BinaryScanner,
    "config": ConfigScanner,
    "pcap":   PCAPScanner,
    "cloud":  CloudScanner,
}

__all__ = [
    "GitScanner", "DockerScanner", "APKScanner", "BinaryScanner",
    "ConfigScanner", "PCAPScanner", "CloudScanner", "ALL_SCANNERS",
]
