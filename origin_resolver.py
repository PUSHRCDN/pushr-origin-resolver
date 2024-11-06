import socket
from dnslib import DNSRecord, DNSHeader, QTYPE, RR, A, AAAA, CNAME

def resolve_cname(cname, upstream_dns, failover_dns):
    """Resolve the CNAME to an IP address."""
    try:
        query = DNSRecord.question(cname, QTYPE.A)
        response = query.send(upstream_dns[0], upstream_dns[1], timeout=2)
        answer = DNSRecord.parse(response)
        
        # Check if there's an A record in the response
        a_records = [rr for rr in answer.rr if rr.rtype == QTYPE.A]
        if a_records:
            return str(a_records[0].rdata)
        else:
            # Attempt failover if no A record found
            response = query.send(failover_dns[0], failover_dns[1], timeout=2)
            answer = DNSRecord.parse(response)
            a_records = [rr for rr in answer.rr if rr.rtype == QTYPE.A]
            if a_records:
                return str(a_records[0].rdata)
    except Exception:
        pass
    return None  # Return None if CNAME cannot be resolved

def recursive_dns_handler(data, default_ip, upstream_dns, failover_dns):
    """Handle incoming DNS requests with recursive lookup and default IP fallback."""
    request = DNSRecord.parse(data)
    question = request.q.qname
    query_type = QTYPE[request.q.qtype]
    
    print(f"Received DNS query for: {question} ({query_type})")
    
    # Return empty response for unsupported types
    if query_type in ["ANY", "TXT"]:
        response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))
        response.add_question(request.q)
        return response.pack()
    
    try:
        # Query primary upstream DNS server
        upstream_response = request.send(upstream_dns[0], upstream_dns[1], timeout=2)
        response = DNSRecord.parse(upstream_response)
        
        # Check for CNAME resolution
        cname_records = [rr for rr in response.rr if rr.rtype == QTYPE.CNAME]
        if cname_records:
            canonical_name = str(cname_records[0].rdata)
            print(f"CNAME record found, resolving {canonical_name}")
            canonical_ip = resolve_cname(canonical_name, upstream_dns, failover_dns)
            if canonical_ip:
                response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))
                response.add_question(request.q)
                response.add_answer(RR(question, QTYPE.A, rdata=A(canonical_ip), ttl=15))
                return response.pack()
        
        # If upstream returned an empty response, try failover
        if len(response.rr) == 0:
            print("Upstream DNS server returned an empty response. Trying failover.")
            failover_response = request.send(failover_dns[0], failover_dns[1], timeout=2)
            response = DNSRecord.parse(failover_response)
        
        # If both upstream and failover return no records, use default IP
        if len(response.rr) == 0:
            print("Both upstream and failover DNS returned empty responses. Returning default IP.")
            response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))
            response.add_question(request.q)
            response.add_answer(RR(question, QTYPE.A, rdata=A(default_ip), ttl=15))
        
        return response.pack()
    
    except Exception as e:
        print(f"Error during DNS resolution: {e}")
        # In case of an error, respond with the default IP
        response = DNSRecord(DNSHeader(id=request.header.id, qr=1, aa=1, ra=1))
        response.add_question(request.q)
        response.add_answer(RR(question, QTYPE.A, rdata=A(default_ip), ttl=15))
        return response.pack()

def run_recursive_dns_server(host, port, default_ip, upstream_dns, failover_dns):
    """Start the DNS server to handle recursive DNS queries."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    print(f"DNS Server running on {host}:{port}...")
    
    while True:
        data, client_address = sock.recvfrom(512)
        response_data = recursive_dns_handler(data, default_ip, upstream_dns, failover_dns)
        sock.sendto(response_data, client_address)

# Example usage:
run_recursive_dns_server('0.0.0.0', 53, '127.0.0.1', ('8.8.8.8', 53), ('1.1.1.1', 53))
