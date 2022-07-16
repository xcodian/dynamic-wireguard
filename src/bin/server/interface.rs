use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};



use log::{debug, info};
use netlink_packet_wireguard::nlas::{
    WgAllowedIp, WgAllowedIpAttrs, WgDeviceAttrs, WgPeer, WgPeerAttrs,
};
use netlink_packet_wireguard::{Wireguard, WireguardCmd};
use x25519_dalek::PublicKey;

use rtnetlink;
use rtnetlink::packet::link::nlas::{Info, InfoKind, Nla};

use genetlink::{self, GenetlinkHandle};
use netlink_packet_core::{NetlinkMessage, NLM_F_REQUEST};
use netlink_packet_generic::GenlMessage;

use futures::stream::TryStreamExt;

use crate::config::ServerConfig;

async fn connect_to_rtnetlink() -> Result<rtnetlink::Handle, Box<dyn Error>> {
    let (rt_conn, rt_handle, _) = rtnetlink::new_connection()?;
    tokio::spawn(rt_conn);

    return Ok(rt_handle);
}

async fn connect_to_genetlink() -> Result<GenetlinkHandle, Box<dyn Error>> {
    let (gen_conn, gen_handle, _) = genetlink::new_connection()?;
    tokio::spawn(gen_conn);

    return Ok(gen_handle);
}

pub async fn create_server_interface(conf: &ServerConfig) -> Result<(), Box<dyn Error>> {
    // open RTNETLINK connection
    let rt_handle = connect_to_rtnetlink().await?;

    // generate request
    let mut add_req = rt_handle.link().add();
    let add_req_msg = add_req.message_mut();

    // set interface name
    add_req_msg.nlas.push(Nla::IfName(conf.if_name.clone()));

    // set type to be wireguard
    add_req_msg
        .nlas
        .push(Nla::Info(vec![Info::Kind(InfoKind::Wireguard)]));

    // set interface as up
    add_req_msg.header.flags = rtnetlink::packet::IFF_UP;
    add_req_msg.header.change_mask = rtnetlink::packet::IFF_UP;

    info!("Creating wireguard interface {}...", conf.if_name);
    // send rtnetlink message to kernel
    if let Err(e) = add_req.execute().await {
        Err(format!("failed to create interface: {}", e.to_string()))?;
    };

    // open netlink connection with wireguard
    let mut nl_handle = connect_to_genetlink().await?;

    // generate "set device" request
    let genl_msg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: vec![
            // by interface name
            WgDeviceAttrs::IfName(conf.if_name.clone()),
            // set server private key
            WgDeviceAttrs::PrivateKey(conf.private_key.to_bytes()),
            WgDeviceAttrs::ListenPort(conf.wg_port),
        ],
    });

    // send netlink message to kernel to configure wireguard
    let mut nl_msg = NetlinkMessage::from(genl_msg);
    nl_msg.header.flags = NLM_F_REQUEST;

    debug!("configuring interface...");
    if let Err(e) = nl_handle.notify(nl_msg).await {
        Err(format!("failed to set configuration: {}", e.to_string()))?;
    }

    // give wireguard device address & mtu:
    // 1. find its index
    let mut links = rt_handle
        .link()
        .get()
        .match_name(conf.if_name.clone())
        .execute();

    // 2. assuming it exists
    if let Ok(get_res) = links.try_next().await {
        let link = get_res.unwrap();

        // 3. add its address
        debug!("assign address: {}/{}", conf.gateway, conf.cidr);
        let addr_add_res = rt_handle
            .address()
            .add(link.header.index, IpAddr::V4(conf.gateway), conf.cidr)
            .execute()
            .await;

        if let Err(e) = addr_add_res {
            Err(format!("failed to set address: {}", e.to_string()))?;
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
            Err(format!("failed to set MTU: {}", e.to_string()))?;
        }
    } else {
        Err("failed to set address: interface deleted while configuring")?;
    }

    return Ok(());
}

pub async fn delete_interface(name: String) -> Result<(), Box<dyn Error>> {
    // open RTNETLINK connection
    let rt_handle = connect_to_rtnetlink().await?;

    // get interface index
    let rsp = rt_handle
        .link()
        .get()
        .match_name(name.clone())
        .execute()
        .try_next()
        .await?;

    if let None = rsp {
        Err("interface does not exist")?;
    }

    let index = rsp.unwrap().header.index;

    // delete interface
    return Ok(rt_handle.link().del(index).execute().await?);
}

pub async fn add_peer_to_interface(
    conf: &ServerConfig,
    ip: Ipv4Addr,
    remote_public: &PublicKey,
) -> Result<(), Box<dyn Error>> {
    let mut nl_handle = connect_to_genetlink().await?;

    // generate "set device" request
    let genl_msg: GenlMessage<Wireguard> = GenlMessage::from_payload(Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas: vec![
            // by interface name
            WgDeviceAttrs::IfName(conf.if_name.clone()),
            // add peer
            WgDeviceAttrs::Peers(vec![WgPeer(vec![
                WgPeerAttrs::PublicKey(remote_public.to_bytes()),
                WgPeerAttrs::AllowedIps(vec![WgAllowedIp(vec![
                    WgAllowedIpAttrs::IpAddr(IpAddr::V4(ip)),
                    WgAllowedIpAttrs::Cidr(32),
                    WgAllowedIpAttrs::Family(2),
                ])]),
            ])]),
        ],
    });

    // send netlink message to kernel to configure wireguard
    let mut nl_msg = NetlinkMessage::from(genl_msg);
    nl_msg.header.flags = NLM_F_REQUEST;
    nl_handle.notify(nl_msg).await?;

    info!("added peer to interface: assigned {}", ip);

    return Ok(());
}
