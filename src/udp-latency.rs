use clap::{arg, Command};

use std::{
    net::{IpAddr, Ipv4Addr},
    thread,
    time::{Duration, SystemTime},
};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use std::net::UdpSocket;

use pnet::datalink::{self, NetworkInterface};
use pnet_macros::{packet};
use pnet_macros_support::types::u32be;

/****************************************************
 * Perf Packet Structure
 ****************************************************/
#[packet]
pub struct Perf {
    id: u32be,
    op: u8,
    #[payload]
    payload: Vec<u8>,
}

#[derive(FromPrimitive)]
enum PerfOp {
    /* Ping, Pong for RTT mode */
    Ping = 0,
    Pong = 1,

    SYN = 99,
    ACK = 100,
}

/****************************************************
 * Main
 ****************************************************/
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
            arg!(msg_size: -b <udp_msg_size> "UDP Message Size(Byte) - default 1440Bytes")
                .required(false)
                .default_value("1440"),
        )
        .arg(
            arg!(interval: -d <delay_interval> "Latency Measurement Interval(sec) - default 1s")
                .required(false)
                .default_value("1"),
        )
        .arg(
            arg!(count: -c <count> "Measurement Count - default 10")
                .required(false)
                .default_value("10"),
        );

    let matched_command = Command::new("latency")
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
            let interval = sub_matches
                .get_one::<String>("interval")
                .unwrap()
                .to_string();
            let count = sub_matches.get_one::<String>("count").unwrap().to_string();

            do_udp_sender(
                iface, dest_ip, dest_port, msg_size, interval, count,
            );
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

    let src_ip_addr = match interface.ips[0].ip() {
        IpAddr::V4(ip4) => ip4,
        IpAddr::V6(_) => todo!(),
    };
    let src_port: u16 = src_port.parse().unwrap();

    let mut recv_buffer: &mut [u8] = &mut [0; 1500];

    let socket = match UdpSocket::bind(format!("{}:{}", src_ip_addr, src_port)) {
        Ok(sock) => sock,
        Err(err) => panic!("UDP Socket binding error: {}", err),
    };

    loop {
        /* Rx */
        let (received_bytes, req_addr) = match socket.recv_from(&mut recv_buffer) {
            Ok((n, addr)) => (n, addr),
            Err(err) => panic!("UDP Recv Error: {}", err),
        };

        let mut perf_pkt = MutablePerfPacket::new(&mut recv_buffer).expect("MutablePerfPacket Error");

        match PerfOp::from_u8(perf_pkt.get_op()) {
            Some(PerfOp::SYN) => {
                perf_pkt.set_op(PerfOp::ACK as u8);
            }
            Some(PerfOp::Ping) => {
                perf_pkt.set_op(PerfOp::Pong as u8);
            }
            _ => {
                continue;
            }
        }

        /* Tx */
        let _ = socket.send_to(&recv_buffer[..received_bytes], req_addr);
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
    interval: String,
    count: String,
) {
    #[derive(PartialEq, Clone)]
    enum SenderState {
        Ready = 0,
        Running = 1,
    }
    let mut state = SenderState::Ready;

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

    let interval: f32 = interval.parse().unwrap();
    let interval: usize = (interval * 1000.0).round() as usize;

    let count: usize = count.parse().unwrap();
    let mut pkt_idx: usize = 1;

    let socket = match UdpSocket::bind(format!("{}:{}", src_ip_addr, src_port)) {
        Ok(sock) => sock,
        Err(err) => panic!("UDP Socket binding error: {}", err),
    };

    /* Session Init & RTT(UDP Ping-Pong) */
    loop {
        if state == SenderState::Running {
            if pkt_idx > count {
                break;
            }

            thread::sleep(Duration::from_millis(interval.try_into().unwrap()));
        }

        /* Tx */
        let mut message = vec![0u8; msg_size];
        let mut perf_pkt =
            MutablePerfPacket::new(&mut message).expect("MutablePerfPacket Error");

        match state {
            SenderState::Ready => {
                perf_pkt.set_id(0 as u32);
                perf_pkt.set_op(PerfOp::SYN as u8);
            }
            SenderState::Running => {
                perf_pkt.set_id(pkt_idx as u32);
                perf_pkt.set_op(PerfOp::Ping as u8);
            }
        }

        // Get Tx Timestamp
        let tx_timestamp = SystemTime::now();
        let _ = socket.send_to(&message, format!("{}:{}", dest_ip_addr, dest_port));

        let pre_state = state.clone();

        /* Rx */
        loop {
            match state {
                SenderState::Ready => {
                    //thread::sleep(Duration::from_millis(100));
                }
                SenderState::Running => {
                    if pre_state != state {
                        break;
                    }
                }
            }

            let mut rx_message = vec![0u8; msg_size];
            let (_received_bytes, _server_addr) = match socket.recv_from(&mut rx_message) {
                Ok((n_bytes, addr)) => (n_bytes, addr),
                Err(err) => panic!("Rx Error : {}", err),
            };

            // Get Rx Timestamp
            let rx_timestamp = SystemTime::now();
            let perf_pkt = PerfPacket::new(&rx_message).expect("PerfPacket Error");

            match PerfOp::from_u8(perf_pkt.get_op()) {
                Some(PerfOp::ACK) => {
                    state = SenderState::Running;
                    break;
                }
                Some(PerfOp::Pong) => {
                    if pkt_idx != perf_pkt.get_id().try_into().unwrap() {
                        println!("Not Matched");
                        continue;
                    }

                    // Calculate RTT
                    let rtt = rx_timestamp.duration_since(tx_timestamp).unwrap();
                    println!(
                        "pkt id[{}]: RTT {}.{:09}s",
                        pkt_idx,
                        rtt.as_secs(),
                        rtt.subsec_nanos()
                        );

                    pkt_idx += 1;
                    break;
                }
                _ => {
                    println!("ERROR");
                    break;
                }
            }
        }
    }
}
