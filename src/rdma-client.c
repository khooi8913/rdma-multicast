#include "rdma-common.h"

const int TIMEOUT_IN_MS = 500; /* ms */

static int on_addr_resolved(struct rdma_cm_id *id);
static int on_connection(struct rdma_cm_id *id);
static int on_disconnect(struct rdma_cm_id *id);
static int on_event(struct rdma_cm_event *event);
static int on_route_resolved(struct rdma_cm_id *id);
static void usage(const char *argv0);

int main(int argc, char **argv) {
    struct addrinfo *addr;
    struct rdma_cm_event *event = NULL;
    struct rdma_cm_id *conn = NULL;
    struct rdma_event_channel *ec = NULL;

    if (argc != 4)
        usage(argv[0]);

    if (strcmp(argv[1], "write") == 0)
        set_mode(M_WRITE);
    else if (strcmp(argv[1], "read") == 0)
        set_mode(M_READ);
    else
        usage(argv[0]);

    TEST_NZ(getaddrinfo(argv[2], argv[3], NULL, &addr)); // RDMA service port's socket address
    TEST_Z(ec = rdma_create_event_channel());
    TEST_NZ(rdma_create_id(ec, &conn, NULL, RDMA_PS_TCP));
    TEST_NZ(rdma_resolve_addr(conn, NULL, addr->ai_addr, TIMEOUT_IN_MS)); // make resolve address
    freeaddrinfo(addr);

  //   enum rdma_cm_event_type {
  //   RDMA_CM_EVENT_ADDR_RESOLVED, // 0
  //   RDMA_CM_EVENT_ADDR_ERROR, // 1
  //   RDMA_CM_EVENT_ROUTE_RESOLVED, // 2
  //   RDMA_CM_EVENT_ROUTE_ERROR, // 3
  //   RDMA_CM_EVENT_CONNECT_REQUEST, // 4
  //   RDMA_CM_EVENT_CONNECT_RESPONSE, // 5
  //   RDMA_CM_EVENT_CONNECT_ERROR, // 6
  //   RDMA_CM_EVENT_UNREACHABLE, // 7
  //   RDMA_CM_EVENT_REJECTED, // 8
  //   RDMA_CM_EVENT_ESTABLISHED, // 9
  //   RDMA_CM_EVENT_DISCONNECTED, // 10
  //   RDMA_CM_EVENT_DEVICE_REMOVAL, // 11
  //   RDMA_CM_EVENT_MULTICAST_JOIN, // 12
  //   RDMA_CM_EVENT_MULTICAST_ERROR, // 13
  //   RDMA_CM_EVENT_ADDR_CHANGE, // 14
  //   RDMA_CM_EVENT_TIMEWAIT_EXIT // 15
  // };

    while (rdma_get_cm_event(ec, &event) == 0) {
        struct rdma_cm_event event_copy;
        memcpy(&event_copy, event, sizeof(*event));
        printf(" --- Event happens (event type : %d) --- \n", event->event);
        rdma_ack_cm_event(event); // free a communication event
        if (on_event(&event_copy))
            break;
    }

    rdma_destroy_event_channel(ec);

    return 0;
}

int on_addr_resolved(struct rdma_cm_id *id) {
    printf("address resolved.\n");

    build_connection(id);
    sprintf(get_local_message_region(id->context), "client%dnooooooooooooooooo", getpid());
    TEST_NZ(rdma_resolve_route(id, TIMEOUT_IN_MS));

    return 0;
}

int on_connection(struct rdma_cm_id *id) {
    on_connect(id->context);
    send_mr(id->context);

    return 0;
}

int on_disconnect(struct rdma_cm_id *id) {
    printf("disconnected.\n");

    destroy_connection(id->context);
    return 1; /* exit event loop */
}

int on_event(struct rdma_cm_event *event) {
    int r = 0;
    if (event->event == RDMA_CM_EVENT_ADDR_RESOLVED) {
        r = on_addr_resolved(event->id);
        printf("**********Event: RDMA_CM_EVENT_ADDR_RESOLVED\n");
        getchar();
    }
    else if (event->event == RDMA_CM_EVENT_ROUTE_RESOLVED) {
        r = on_route_resolved(event->id);
        printf("**********Event: RDMA_CM_EVENT_ROUTE_RESOLVED\n");
        getchar();
    }
    else if (event->event == RDMA_CM_EVENT_ESTABLISHED) {
        r = on_connection(event->id);
        printf("**********Event: RDMA_CM_EVENT_ESTABLISHED\n");
        getchar();
    }
    else if (event->event == RDMA_CM_EVENT_DISCONNECTED) {
        r = on_disconnect(event->id);
        printf("**********Event: RDMA_CM_EVENT_DISCONNECTED\n");
        getchar();
    }
    else {
        die("on_event: unknown event.");
    }

    return r;
}

int on_route_resolved(struct rdma_cm_id *id) {
    struct rdma_conn_param cm_params;

    printf("route resolved.\n");
    build_params(&cm_params);
    TEST_NZ(rdma_connect(id, &cm_params));

    return 0;
}

void usage(const char *argv0) {
    fprintf(stderr, "usage: %s <mode> <server-address> <server-port>\n  mode = \"read\", \"write\"\n", argv0);
    exit(1);
}
