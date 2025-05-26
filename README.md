# AegisNet - Encrypted Decentralized Communication Network

A secure, anonymous, and censorship-resistant communication platform that operates entirely off-grid without relying on TOR, I2P, or centralized services.

## Features

- End-to-end encryption using NaCl (Curve25519 + XSalsa20 + Poly1305)
- Custom Rotten Routing™ protocol for anonymous message routing
- Terminal and web browser interfaces
- Local web proxy server (localhost:7938)
- No central server - fully peer-to-peer over UDP
- Multi-hop routing with 2-3 random encrypted relays
- Self-destructing messages with TTL

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aegisnet.git
cd aegisnet
```

2. Create a virtual environment and activate it:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Terminal Mode
```bash
python aegisnet_ghostmode.py
```

### Web Interface
After joining a room, access the web interface at:
```
http://localhost:7938
```

## Security Model

- End-to-End Encryption: All messages are encrypted with recipient's public key
- Multi-hop Routing: Messages pass through 2-3 random encrypted relays
- No IP Exposure: Relays only know the next hop
- Local-Only Proxy: Web interface runs only on localhost
- Message TTL: Messages self-destruct after TTL or 60s

## Room URLs

Room URLs follow the format: `[random16chars].aegisnet`
These are accessible via the local proxy at localhost:7938.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the process for submitting pull requests.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Notice

This software is provided as-is. While we implement strong security measures, no system is completely secure. Use at your own risk and verify the code meets your security requirements. 