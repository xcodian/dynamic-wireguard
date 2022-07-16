use std::net::{IpAddr, Ipv4Addr, SocketAddr};



use dynamic_wireguard::wgconfig::WgAddrConfig;

use log::{debug, error, info};
use netlink_packet_wireguard::nlas::{
    WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs,
};
use netlink_packet_wireguard::{Wireguard, WireguardCmd};
use x25519_dalek::{PublicKey, StaticSecret};

use rtnetlink;
use rtnetlink::packet::link::nlas::{Info, InfoKind, Nla};

use genetlink;
use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use futures::stream::TryStreamExt;

pub async fn create_interface(
    config: &WgAddrConfig,
    local_private: &StaticSecret,
    remote_public: &PublicKey,
    remote_addr: Ipv4Addr,
) {
    // let if_name = "wgdyn0".to_string();

    // open RTNETLINK connection
    let rt_maybe = rtnetlink::new_connection();

    if let Err(e) = rt_maybe {
        error!("Failed to open RTNETLINK connection: {}", e.to_string());
        return;
    }

    let (rt_conn, rt_handle, _) = rt_maybe.unwrap();
    tokio::spawn(rt_conn);

    // // find free interface name
    // let mut if_num = 0;
    // let mut if_name;

    // loop {
    //     if_name = "wgdyn".to_string() + &if_num.to_string();

    //     let mut links = rt_handle.link().get().match_name(if_name.clone()).execute();

    //     let get_res = links.try_next().await;

    //     if let Err(_) = get_res {
    //         // found free interface name
    //         break;
    //     }

    //     if_num += 1;
    // }

    let if_name = "wgdyn0".to_string();

    // generate request
    let mut add_req = rt_handle.link().add();
    let add_req_msg = add_req.message_mut();

    // set interface name
    add_req_msg.nlas.push(Nla::IfName(if_name.clone()));

    // set type to be wireguard
    add_req_msg
        .nlas
        .push(Nla::Info(vec![Info::Kind(InfoKind::Wireguard)]));

    // set interface as up
    add_req_msg.header.flags = rtnetlink::packet::IFF_UP;
    add_req_msg.header.change_mask = rtnetlink::packet::IFF_UP;

    info!("Creating WireGuard interface {}...", if_name);
    // send rtnetlink message to kernel
    if let Err(e) = add_req.execute().await {
        error!("Failed to create {}: {}", if_name, e.to_string());
        return;
    };

    // open netlink connection with wireguard
    let nl_maybe = genetlink::new_connection();

    if let Err(e) = nl_maybe {
        error!("Failed to open WG NETLINK connection: {}", e.to_string());
        return;
    }

    let (nl_conn, mut nl_handle, _) = nl_maybe.unwrap();
    tokio::spawn(nl_conn);

    let genl_msg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: vec![
            WgDeviceAttrs::IfName(if_name.clone()),
            WgDeviceAttrs::PrivateKey(local_private.to_bytes()),
            WgDeviceAttrs::Peers(vec![WgPeer(vec![
                WgPeerAttrs::PublicKey(remote_public.to_bytes()),
                WgPeerAttrs::Endpoint(SocketAddr::new(
                    IpAddr::V4(remote_addr),
                    config.wg_endpoint_port,
                )),
                WgPeerAttrs::AllowedIps(vec![WgAllowedIp(vec![
                    WgAllowedIpAttrs::IpAddr(IpAddr::V4(config.internal_gateway)),
                    WgAllowedIpAttrs::Cidr(32),
                    WgAllowedIpAttrs::Family(2),
                ])]),
            ])]),
        ],
    });

    // send netlink message to kernel to configure wireguard
    let mut nl_msg = NetlinkMessage::from(genl_msg);
    nl_msg.header.flags = NLM_F_REQUEST;

    debug!("configuring interface...");
    if let Err(e) = nl_handle.notify(nl_msg).await {
        error!("Failed to set WireGuard configuration: {}", e.to_string());
        return;
    }

    // give wireguard device address & mtu:
    // 1. find its index
    let mut links = rt_handle.link().get().match_name(if_name.clone()).execute();

    // 2. assuming it exists
    if let Ok(get_res) = links.try_next().await {
        let link = get_res.unwrap();

        // 3. add its address
        debug!(
            "assigning address {}...",
            config.assigned_address.to_string() + "/24"
        );
        let addr_add_res = rt_handle
            .address()
            .add(link.header.index, IpAddr::V4(config.assigned_address), 24)
            .execute()
            .await;

        if let Err(e) = addr_add_res {
            error!("Failed to assign address: {}", e.to_string());
            return;
        }

        // 4. set device mtu
        debug!("assign mtu: {}", 1420u16.to_string());
        let mtu_res = rt_handle
            .link()
            .set(link.header.index)
            .mtu(1420)
            .execute()
            .await;

        if let Err(e) = mtu_res {
            error!("Failed to set MTU: {}", e.to_string());
            return;
        }
    } else {
        error!("Failed to set interface address: interface disappeared while configuring");
        return;
    }
}
