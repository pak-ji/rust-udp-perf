#![allow(static_mut_refs)]

use clap::{arg, Command};

use std::{
    net::{IpAddr, Ipv4Addr},
    thread,
    time::{Duration, Instant},
};

use std::net::UdpSocket;
use pnet::{
    datalink,
    datalink::{NetworkInterface},
};

static mut STATS_RUNNING: bool = false;

struct Statistics {
    pkt_count: usize,
    total_bytes: usize,
    duration: usize,
}

static mut STATS: Statistics = Statistics {
    pkt_count: 0,
    total_bytes: 0,
    duration: 0,
};

fn main() {
    let receiver_command = Command::new("receiver")
        .about("Receiver mode")
        .arg(arg!(iface: -i <iface> "Interface to use").required(true))
        .arg(arg!(src_port: <source_port> "Source Port Number").required(true));

    let sender_command = Command::new("sender")
        .about("Sender mode")
        .arg(arg!(iface: -i <iface> "Interface to use").required(true))
        .arg(arg!(dest_ip: <destination_ip> "Destination IP Address").required(true))
        .arg(arg!(dest_port: <destination_port> "Destination Port Number").required(true))
        .arg(
            arg!(msg_size: -b <udp_message_size> "UDP Message Size(Byte) - default 1440Bytes")
                .required(false)
                .default_value("1440"),
        );

    let matched_command = Command::new("throughput")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(receiver_command)
        .subcommand(sender_command)
        .get_matches();

    match matched_command.subcommand() {
        Some(("receiver", sub_matches)) => {
            let iface = sub_matches.get_one::<String>("iface").unwrap().to_string();
            let src_port = sub_matches
                .get_one::<String>("src_port")
                .unwrap()
                .to_string();

            do_udp_receiver(iface, src_port);
        }
        Some(("sender", sub_matches)) => {
            let iface = sub_matches.get_one::<String>("iface").unwrap().to_string();
            let dest_ip = sub_matches
                .get_one::<String>("dest_ip")
                .unwrap()
                .to_string();
            let dest_port = sub_matches
                .get_one::<String>("dest_port")
                .unwrap()
                .to_string();
            let msg_size = sub_matches
                .get_one::<String>("msg_size")
                .unwrap()
                .to_string();

            do_udp_sender(iface, dest_ip, dest_port, msg_size);
        }
        _ => todo!(),
    }
}

/****************************************************
 * UDP Receiver
 ****************************************************/
fn do_udp_receiver(iface_name: String, src_port: String) {
    let interface_name_match = |iface: &NetworkInterface| iface.name == iface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_name_match).unwrap();

    let src_ip_addr = interface.ips[0].ip();
    let src_port: u16 = src_port.parse().unwrap();

    const ETH_HDR_LEN: usize = 14;
    const IP_HDR_LEN: usize = 20;
    const UDP_HDR_LEN: usize = 8;
    const TOTAL_HDR_LEN: usize = ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN;

    let mut recv_buffer: &mut [u8] = &mut [0; 1500];

    let socket = match UdpSocket::bind(format!("{}:{}", src_ip_addr, src_port)) {
        Ok(sock) => sock,
        Err(err) => panic!("UDP Socket binding error: {}", err),
    };

    unsafe {
        STATS.duration = Duration::from_secs(100000).as_secs() as usize;
        STATS.pkt_count = 0;
        STATS.total_bytes = 0;
        STATS_RUNNING = true;
    }
    thread::spawn(stats_thread);

    loop {
        let (received_bytes, _req_addr) = match socket.recv_from(&mut recv_buffer) {
            Ok((n, addr)) => (n, addr),
            Err(err) => panic!("UDP Recv Error: {}", err),
        };

        unsafe {
            STATS.pkt_count += 1;
            STATS.total_bytes += received_bytes + TOTAL_HDR_LEN;
        }
    }
}

fn stats_thread() {
    let stats = unsafe { &mut STATS };
    let mut last_bytes = 0;
    let mut last_packets = 0;
    let start_time = Instant::now();
    let mut last_time = start_time;

    const SECOND: Duration = Duration::from_secs(1);

    while unsafe { STATS_RUNNING } {
        let elapsed = last_time.elapsed();

        if elapsed < SECOND {
            thread::sleep(SECOND - elapsed);
        }

        last_time = Instant::now();

        let bytes = stats.total_bytes;
        let bits = (bytes - last_bytes) * 8;
        let total_packets = stats.pkt_count;
        let packets = total_packets - last_packets;

        let lap = start_time.elapsed().as_secs();

        if lap > stats.duration as u64 {
            unsafe {
                STATS_RUNNING = false;
            }
            break;
        }

        println!(
            "{0}s: \
            {1} pps {2} bps",
            lap,
            //packets.to_formatted_string(&Locale::en),
            packets,
            //bits.to_formatted_string(&Locale::en),
            bits,
        );

        last_bytes = bytes;
        last_packets = total_packets;
    }
}

/****************************************************
 * UDP Sender
 ****************************************************/
fn do_udp_sender(
    iface_name: String,
    dest_ip: String,
    dest_port: String,
    msg_size: String,
) {
    let interface_name_match = |iface: &NetworkInterface| iface.name == iface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_name_match).unwrap();

    let src_ip_addr: Ipv4Addr = match interface.ips[0].ip() {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => todo!(),
    };
    let src_port: u16 = dest_port.parse().unwrap();
    let src_port = src_port + 1;

    let dest_ip_addr: Ipv4Addr = dest_ip.parse().unwrap();
    let dest_port: u16 = dest_port.parse().unwrap();

    let msg_size: usize = msg_size.parse().unwrap();

    let socket = match UdpSocket::bind(format!("{}:{}", src_ip_addr, src_port)) {
        Ok(sock) => sock,
        Err(err) => panic!("UDP Socket binding error: {}", err),
    };

    loop {
        let buffer = vec![0u8; msg_size];
        let _ = socket.send_to(&buffer, format!("{}:{}", dest_ip_addr, dest_port));
    }
}
