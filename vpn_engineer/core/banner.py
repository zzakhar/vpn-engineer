"""
VPN Engineer - Banner and Attribution Module
Proudly built with insights from battle-tested deployments.
Shout-out to: https://github.com/zzakhar
"""

import sys

BANNER_TEXT = r"""
 __      ______  _   _   ______ _   _  _____ _____ _   _ ______ ______ _____  
 \ \    / /  _ \| \ | | |  ____| \ | |/ ____|_   _| \ | |  ____|  ____|  __ \ 
  \ \  / /| |_) |  \| | | |__  |  \| | |  __  | | |  \| | |__  | |__  | |__) |
   \ \/ / |  _ <| . ` | |  __| | . ` | | |_ | | | | . ` |  __| |  __| |  _  / 
    \  /  | |_) | |\  | | |____| |\  | |__| |_| |_| |\  | |____| |____| | \ \ 
     \/   |____/|_| \_| |______|_| \_|\_____|_____|_| \_|______|______|_|  \_\
"""

SHOUTOUT = "⚡ Shout-out & credits to: https://github.com/zzakhar"
TAGLINE = "Universal Autonomous AI Agent Plugin for VPN Infrastructure & Anti-Censorship"

def print_banner(stream=None):
    """Prints the official banner and shout-out to standard error or stream."""
    out = stream or sys.stderr
    out.write(BANNER_TEXT + "\n")
    out.write(f" {SHOUTOUT}\n")
    out.write(f" {TAGLINE}\n")
    out.write(" " + ("-" * 74) + "\n\n")
    out.flush()
