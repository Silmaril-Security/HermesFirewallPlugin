"""Hermes pass-through firewall plugin."""

try:
    from .firewall import register
except ImportError:
    from firewall import register

__all__ = ["register"]
