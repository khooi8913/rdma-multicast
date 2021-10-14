/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>

/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
typedef bit<16> ether_type_t;
typedef bit<8> ip_protocol_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ip_protocol_t IP_PROTOCOLS_UDP = 0x11;
const bit<16> UDP_ROCE_V2 = 4791;

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> udp_total_len;
    bit<16> checksum;
}

header ib_bth_h {
    bit<8>  opcode; // 00001010 RC RDMA Write, 00101010 UC RDMA Write, 00000100 RC SEND
    bit<8>  flags;  // 1 bit solicited event, 1 bit migreq, 2 bit padcount, 4 bit headerversion
    bit<16> partition_key;
    bit<8>  reserved0;
    bit<24> destination_qp;
    bit<1>  ack_request; 
    bit<7>  reserved1;   
    bit<24> packet_seqnum;
}

header ib_reth_h {
    bit<64> virtual_addr;
    bit<32> remote_key;
    bit<32> dma_length;
}

header data_h {
    bit<128> data; 
}

header icrc_h {
    bit<32> icrc;
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    udp_h           udp;
    ib_bth_h        bth;
    ib_reth_h       reth;
    data_h          data;
    icrc_h          icrc;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<10> mirror_session;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         meta,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);

        meta.mirror_session = 0;

        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_ROCE_V2 : parse_bth;
            default : accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            0x0a : parse_reth;
            default  : accept;
        }
    }

    state parse_reth {
        pkt.extract(hdr.reth);
        transition parse_data;
    }

    state parse_data {
        pkt.extract(hdr.data);
        transition parse_icrc;
    }

    state parse_icrc {
        pkt.extract(hdr.icrc);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

    action mirror() {
        ig_dprsr_md.mirror_type = 1;
        meta.mirror_session = 10w333;
    }

    action multicast(MulticastGroupId_t mcast_grp) {
        ig_tm_md.mcast_grp_a       = mcast_grp;
        ig_tm_md.level2_exclusion_id = 0xFF;

        mirror();
    }

    table multicast_forward {
        key = {
            hdr.ipv4.dst_addr : exact;
            hdr.udp.dst_port : exact;
        }
        actions = {
            multicast;
            NoAction;
        }
        const entries = {
            (0xe001ffff, 4791) : multicast(224);    // 224.1.255.255
        }
        size = 512;
    }

    action l2_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port=port;

        mirror();
    }

    table l2_forwarding {
        key = {
            hdr.ethernet.dst_addr : exact;
        }
        actions = {
            l2_forward;
            NoAction;
        }
        const entries = {
            0xb8cef6046bd0 : l2_forward(132);   // lumos - ens2f0 b8:ce:f6:04:6b:d0
            0xb8cef6046bd1 : l2_forward(133);   // lumos - ens2f1 b8:ce:f6:04:6b:d1
            0xb8cef6046c04 : l2_forward(134);   // patronus - ens2f0 b8:ce:f6:04:6c:04
            0xb8cef6046c05 : l2_forward(135);   // patronus - ens2f1 b8:ce:f6:04:6c:05
        }
    }

    apply {
        if(!multicast_forward.apply().hit) {
            l2_forwarding.apply();
        }

        // if(ig_intr_md.ingress_port == 132) {
        //     ig_dprsr_md.mirror_type = 1;
        //     meta.mirror_session = 10w333;
        //     ig_tm_md.ucast_egress_port = 134;
        // } else if (ig_intr_md.ingress_port == 134) {
        //     ig_dprsr_md.mirror_type = 1;
        //     meta.mirror_session = 10w333;
        //     ig_tm_md.ucast_egress_port = 132;
        // } else {
        //     ig_dprsr_md.drop_ctl = 0x0;
        // }   

        // ig_tm_md.bypass_egress = 1;
    }
}

    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      meta,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        if(ig_dprsr_md.mirror_type == 1) {      // different mirror types can define different sets of headers
            mirror.emit(meta.mirror_session);   // which session?
        }

        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
    ethernet_h      ethernet;
    ipv4_h          ipv4;
    udp_h           udp;
    ib_bth_h        bth;
    ib_reth_h       reth;
    data_h          data;
    icrc_h          icrc;
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
    bit<10> mirror_session;
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTOCOLS_UDP : parse_udp;
            default : accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            UDP_ROCE_V2 : parse_bth;
            default : accept;
        }
    }

    state parse_bth {
        pkt.extract(hdr.bth);
        transition select(hdr.bth.opcode) {
            0x0a : parse_reth;
            default  : accept;
        }
    }

    state parse_reth {
        pkt.extract(hdr.reth);
        transition parse_data;
    }

    state parse_data {
        pkt.extract(hdr.data);
        transition parse_icrc;
    }

    state parse_icrc {
        pkt.extract(hdr.icrc);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{

    bit<32> tmp1 = 0;
    bit<32> tmp2 = 0;
    bit<32> tmp3 = 0;
    bit<32> tmp4 = 0; 
    bit<64> tmp5 = 0;

    CRCPolynomial<bit<32>>(
        coeff = 0x04C11DB7,
        reversed = true,
        msb = false,
        extended = false,
        init = 0xFFFFFFFF,
        xor = 0xFFFFFFFF
    ) poly;
    Hash<bit<32>>(HashAlgorithm_t.CUSTOM, poly) crc_hash;

    action calculate_crc() {
        hdr.icrc.setValid();
        hdr.icrc.icrc = crc_hash.get({
        64w0xffffffffffffffff, // infiniband lrh
        hdr.ipv4.version,
        hdr.ipv4.ihl,
        8w0xff,     // tos
        hdr.ipv4.total_len,
        hdr.ipv4.identification,
        hdr.ipv4.flags,
        hdr.ipv4.frag_offset,
        8w0xff, // ttl
        hdr.ipv4.protocol,
        16w0xffff,  // checksum
        hdr.ipv4.src_addr,
        hdr.ipv4.dst_addr,
        hdr.udp.src_port,
        hdr.udp.dst_port,
        hdr.udp.udp_total_len,
        16w0xffff,  // udp checksum
        hdr.bth.opcode,
        hdr.bth.flags,
        hdr.bth.partition_key,
        8w0xff,     // reserved0, resv8a?
        hdr.bth.destination_qp,
        hdr.bth.ack_request,
        hdr.bth.reserved1,
        hdr.bth.packet_seqnum,
        hdr.reth.virtual_addr,
        hdr.reth.remote_key,
        hdr.reth.dma_length,
        hdr.data.data
        });
    }	

    action swap_crc() {
        tmp1 = hdr.icrc.icrc & 0x000000FF;
        tmp2 = hdr.icrc.icrc & 0x0000FF00;
        tmp3 = hdr.icrc.icrc & 0x00FF0000;
        tmp4 = hdr.icrc.icrc & 0xFF000000;
    }

    action swap2_crc() {
        tmp1 = tmp1 << 24;
        tmp2 = tmp2 << 8;
        tmp3 = tmp3 >> 8;
        tmp4 = tmp4 >> 24;
    }

    action swap3_crc() {
        tmp1 = tmp1 | tmp2;
        tmp3 = tmp3 | tmp4;
    }

    action swap4_crc() {
	    hdr.icrc.icrc = tmp1 | tmp3;
    }

    action translate(bit<24> qp, bit<24> seq, bit<64> virtual_addr, bit<32> remote_key) {
        hdr.bth.destination_qp = qp;
        hdr.bth.packet_seqnum = seq;
        hdr.reth.remote_key = remote_key;
        hdr.reth.virtual_addr = virtual_addr;
    }

    table rdma_translate {
        key = {
            eg_intr_md.egress_port : exact;
            hdr.ipv4.dst_addr   : exact;
        }
        actions = {
            translate;
            NoAction;
        }
        size = 512;
    }

    action swap(bit<48> dst_mac, bit<32> dst_ip) {
        hdr.ethernet.dst_addr = dst_mac;
        hdr.ipv4.dst_addr = dst_ip;
    }

    table swap_dst_mac_ip {
        key = {
           eg_intr_md.egress_port : exact; 
        }
        actions = {
            swap;
            NoAction;
        }
        const entries = {
            132 : swap(0xb8cef6046bd0, 0x0a0a0a01); // 132 - 10.10.10.1
            133 : swap(0xb8cef6046bd1, 0x0a0a0a02); // 133 - 10.10.10.2
            134 : swap(0xb8cef6046c04, 0x0a0a0a03); // 133 - 10.10.10.3
            135 : swap(0xb8cef6204c05, 0x0a0a0a04); // 134 - 10.10.10.4
        }
        size = 512;
    }

    action mirror() {
        eg_dprsr_md.mirror_type = 1;
        meta.mirror_session = 10w333;
    }
    
    apply {
        if(rdma_translate.apply().hit) {
            swap_dst_mac_ip.apply();
            calculate_crc();
            swap_crc();
            swap2_crc();
            swap3_crc();
            swap4_crc();
        }

        if(hdr.udp.dst_port == 4791) {
            mirror();
        }

        // if(hdr.reth.isValid()) {
        //     calculate_crc();
        //     swap_crc();
        //     swap2_crc();
        //     swap3_crc();
        //     swap4_crc();
        // }

        // if(eg_intr_md.egress_port == 132) {
        //     eg_dprsr_md.mirror_type = 1;
        //     meta.mirror_session = 10w333;
        // } else if (eg_intr_md.egress_port == 134) {
        //     eg_dprsr_md.mirror_type = 1;
        //     meta.mirror_session = 10w333;
        // }
        
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    Mirror() mirror;

    apply {
        if(eg_dprsr_md.mirror_type == 1) {
            mirror.emit(meta.mirror_session);
        }
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
