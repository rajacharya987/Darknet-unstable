function FindProxyForURL(url, host) {
            if (shExpMatch(host, "*.aegisnet")) {
                return "PROXY localhost:8889";
            }
            return "DIRECT";
        }