from setuptools import setup, find_packages

setup(
    name="vpn-engineer",
    version="1.0.0",
    description="Universal Autonomous AI Agent Plugin for VPN Infrastructure & Anti-Censorship",
    author="zzakhar",
    author_email="dev@quietlinuxlab.xyz",
    url="https://github.com/zzakhar",
    license="MIT",
    packages=find_packages(),
    install_requires=[
        "click>=8.0.0",
        "paramiko>=2.8.0",
        "pyyaml>=6.0"
    ],
    entry_points={
        "console_scripts": [
            "vpn-engineer = vpn_engineer.cli:main"
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12"
    ]
)
