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
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
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
            0x00001010 : parse_reth;
            0x00101010 : parse_reth;
            default  : accept;
        }
    }

    state parse_reth {
        pkt.extract(hdr.reth);
        transition accept;
    }

    // state parse_aeth {
    // TODO
    // }

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

    

    apply {
        if(ig_intr_md.ingress_port == 132) {
            ig_tm_md.ucast_egress_port = 134;
        } else if (ig_intr_md.ingress_port == 134) {
            ig_tm_md.ucast_egress_port = 132;
        } else {
            ig_dprsr_md.drop_ctl = 0x0;
        }
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
    apply {
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
            // 8w00101010 : parse_reth;
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

    apply {
        if(hdr.reth.isValid()) {
            calculate_crc();
            swap_crc();
            swap2_crc();
            swap3_crc();
            swap4_crc();
        }
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
    apply {
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
