import socket
import re


class ASN_Finder:
    def get_asn(self, ip):
        authoritative_whois = self._get_whois_server(ip)
        if authoritative_whois:
            whois_response = self._query_whois_server(authoritative_whois, ip)
            if not whois_response:
                return None

            as_number = self._parse_asn(whois_response)
            if as_number:
                return f"AS{as_number}"

        return None

    def _query_whois_server(self, whois_server, query):
        response = ""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5)
                s.connect((whois_server, 43))
                s.sendall((query + "\r\n").encode('utf-8'))
                while True:
                    data = s.recv(4096)
                    if not data:
                        break
                    response += data.decode('utf-8', errors='ignore')
        except:
            pass
        return response

    def _get_whois_server(self, ip):
        response = self._query_whois_server("whois.iana.org", ip)
        if not response:
            return None

        match = re.search(r'refer:\s*(\S+)', response, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        match = re.search(r'whois:\s*(\S+)', response, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        return None

    def _parse_asn(self, response):
        patterns = [
            r'origin\s*:\s*(?=AS)?(\d+)',
            r'originAS\s*:\s*AS(\d+)',
            r'origin:\s*AS-(\d+)',
            r'AUT-NUM:\s*AS(\d+)',
            r'AS Number:\s*(\d+)',
        ]
        as_nums = set()
        for pattern in patterns:
            matches = re.findall(pattern, response, re.IGNORECASE)
            for match in matches:
                as_nums.add(match)

        if as_nums:
            return sorted(as_nums, key=lambda x: -int(x))[0]
        return None

