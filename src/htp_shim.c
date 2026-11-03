/*
 * Accessors over libhtp structures, so that Rust never depends on their C
 * layout (and on macros such as bstr_ptr). Field numbers are mirrored in
 * src/http.rs.
 */

#include "htp.h"
#include "htp_private.h"

const unsigned char *fr_bstr_ptr(const bstr *b) { return bstr_ptr(b); }
size_t fr_bstr_len(const bstr *b) { return bstr_len(b); }

const bstr *fr_tx_bstr(const htp_tx_t *tx, int field) {
    switch (field) {
    case 0: return tx->request_line;
    case 1: return tx->request_method;
    case 2: return tx->request_uri;
    case 3: return tx->request_protocol;
    case 4: return tx->request_content_type;
    case 5: return tx->request_auth_username;
    case 6: return tx->request_auth_password;
    case 7: return tx->request_hostname;
    case 8: return tx->response_line;
    case 9: return tx->response_protocol;
    case 10: return tx->response_status;
    case 11: return tx->response_message;
    case 12: return tx->response_content_type;
    default: return NULL;
    }
}

int64_t fr_tx_int(const htp_tx_t *tx, int field) {
    switch (field) {
    case 0: return tx->request_ignored_lines;
    case 1: return tx->request_method_number;
    case 2: return tx->request_protocol_number;
    case 3: return tx->is_protocol_0_9;
    case 4: return tx->request_message_len;
    case 5: return tx->request_entity_len;
    case 6: return tx->request_transfer_coding;
    case 7: return tx->request_content_encoding;
    case 8: return tx->request_content_length;
    case 9: return tx->request_auth_type;
    case 10: return tx->request_port_number;
    case 11: return tx->response_ignored_lines;
    case 12: return tx->response_protocol_number;
    case 13: return tx->response_status_number;
    case 14: return tx->response_status_expected_number;
    case 15: return tx->seen_100continue;
    case 16: return tx->response_message_len;
    case 17: return tx->response_entity_len;
    case 18: return tx->response_content_length;
    case 19: return tx->response_transfer_coding;
    case 20: return tx->response_content_encoding;
    case 21: return (int64_t) tx->flags;
    case 22: return tx->request_progress;
    case 23: return tx->response_progress;
    case 24: return (int64_t) tx->index;
    default: return 0;
    }
}

const htp_uri_t *fr_tx_uri(const htp_tx_t *tx, int raw) {
    return raw ? tx->parsed_uri_raw : tx->parsed_uri;
}

const bstr *fr_uri_bstr(const htp_uri_t *u, int field) {
    switch (field) {
    case 0: return u->scheme;
    case 1: return u->username;
    case 2: return u->password;
    case 3: return u->hostname;
    case 4: return u->port;
    case 5: return u->path;
    case 6: return u->query;
    case 7: return u->fragment;
    default: return NULL;
    }
}

int fr_uri_port_number(const htp_uri_t *u) { return u->port_number; }

/* 0: request headers, 1: response headers, 2: request cookies. */
const htp_table_t *fr_tx_table(const htp_tx_t *tx, int which) {
    switch (which) {
    case 0: return tx->request_headers;
    case 1: return tx->response_headers;
    case 2: return tx->request_cookies;
    default: return NULL;
    }
}

size_t fr_table_size(const htp_table_t *t) { return t == NULL ? 0 : htp_table_size(t); }

/* Header tables hold htp_header_t; cookie tables hold the value bstr. */
void fr_table_entry(const htp_table_t *t, size_t i, int headers, const bstr **name, const bstr **value) {
    bstr *key = NULL;
    void *v = htp_table_get_index(t, i, &key);
    if (headers) {
        const htp_header_t *h = v;
        *name = h == NULL ? NULL : h->name;
        *value = h == NULL ? NULL : h->value;
    } else {
        *name = key;
        *value = v;
    }
}

htp_tx_t *fr_tx_data_tx(const htp_tx_data_t *d) { return d->tx; }
const unsigned char *fr_tx_data_ptr(const htp_tx_data_t *d) { return d->data; }
size_t fr_tx_data_len(const htp_tx_data_t *d) { return d->len; }

void *fr_tx_flow(const htp_tx_t *tx) { return htp_connp_get_user_data(tx->connp); }

/* Transactions still held by the connection (NULL entries were destroyed). */
size_t fr_connp_tx_count(const htp_connp_t *connp) {
    return connp->conn == NULL ? 0 : htp_list_size(connp->conn->transactions);
}

htp_tx_t *fr_connp_tx(const htp_connp_t *connp, size_t i) {
    return htp_list_get(connp->conn->transactions, i);
}

/*
 * After htp_connp_req_data() returns HTP_STREAM_TUNNEL from CONNECT
 * probing, the probed bytes are counted as consumed but belong to the
 * tunnel: they are in in_buf, or still in the current chunk between the
 * consume and read offsets (see htp_connp_req_consolidate_data).
 */
size_t fr_connp_req_tunnel_prefix(const htp_connp_t *connp, const unsigned char **data) {
    if (connp->in_buf != NULL) {
        *data = connp->in_buf;
        return connp->in_buf_size;
    }
    *data = connp->in_current_data + connp->in_current_consume_offset;
    return connp->in_current_read_offset - connp->in_current_consume_offset;
}
