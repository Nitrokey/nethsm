(** Stack with IP layers modified to allow (at least) TCP packets that are not
    for us to reach the TCP layer for routing. *)

module Make (Net : Mirage_net.S) (Eth : Ethernet.S) (Arp : Arp.S) = struct
  module V4 = struct
    include Static_ipv4.Make (Eth) (Arp)

    let f_cache = ref (Fragments.Cache.empty (1024 * 256))

    (* Copy of Static_ipv4.input with the IP check removed *)
    let input (t : t) ~tcp ~udp ~default buf =
      match Ipv4_packet.Unmarshal.of_cstruct buf with
      | Error s ->
          Logs.info (fun m ->
              m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
          Lwt.return_unit
      | Ok (packet, payload) -> (
          if Cstruct.length payload = 0 then (
            Logs.debug (fun m ->
                m "dropping zero length IPv4 frame %a" Ipv4_packet.pp packet);
            Lwt.return_unit)
          else
            let ts = Mirage_mtime.elapsed_ns () in
            let cache, res = Fragments.process !f_cache ts packet payload in
            f_cache := cache;
            match res with
            | None -> Lwt.return_unit
            | Some (packet, payload) -> (
                let src, dst = (packet.src, packet.dst) in
                match Ipv4_packet.Unmarshal.int_to_protocol packet.proto with
                | Some `TCP -> tcp ~src ~dst payload
                | Some `UDP -> udp ~src ~dst payload
                | Some `ICMP | None ->
                    default ~proto:packet.proto ~src ~dst payload))
  end

  module NDP = struct
    include Ndpv6

    let orig_handle = handle

    let get_dst buf =
      if
        (Cstruct.length buf < Ipv6_wire.sizeof_ipv6
        || Cstruct.length buf < Ipv6_wire.sizeof_ipv6 + Ipv6_wire.get_len buf)
        || Int32.logand (Ipv6_wire.get_version_flow buf) 0xF0000000l
           <> 0x60000000l
      then None
      else
        let buf =
          Cstruct.sub buf 0 (Ipv6_wire.sizeof_ipv6 + Ipv6_wire.get_len buf)
        in
        let src = Ipv6_wire.get_src buf in
        let dst = Ipv6_wire.get_dst buf in
        if Ipaddr.V6.Prefix.(mem src multicast) then None else Some dst

    (* This is a hack that allows the IPv6 stack to accept packets not meant for
       us by:
        - rewriting the packet so the dst address to our IP (to avoid next step
          dropping the packet)
        - letting the original NDP stack handle it
        - revert the dst to the original one before processing by upper layers
          (TCP, UDP, etc.)
       It is on the platform to be careful about what it sends to the internal
       interface! *)
    let handle ~now ctx buf =
      match get_ip ctx with
      | [] -> orig_handle ~now ctx buf
      | my_ip :: _ -> (
          match get_dst buf with
          | None -> orig_handle ~now ctx buf
          | Some orig_dst ->
              Ipv6_wire.set_dst buf my_ip;
              let ctx', bufs, events = orig_handle ~now ctx buf in
              let events =
                List.map
                  (function
                    | `Tcp (src, dst, buf) -> `Tcp (src, orig_dst, buf)
                    | `Udp (src, dst, buf) -> `Udp (src, orig_dst, buf)
                    | `Default (proto, src, dst, buf) ->
                        `Default (proto, src, orig_dst, buf))
                  events
              in
              Ipv6_wire.set_dst buf orig_dst;
              (ctx', bufs, events))
  end

  module V6 = Ipv6_custom.Make (Net) (Eth) (Ndpv6)
  module Icmp = Icmpv4.Make (V4)
  module V4V6 = Tcpip_stack_direct.IPV4V6 (V4) (V6)
  module Tcp = Tcp.Flow.Make (V4V6)
  module Udp = Udp.Make (V4V6)

  include
    Tcpip_stack_direct.MakeV4V6 (Net) (Eth) (Arp) (V4V6) (Icmp) (Udp) (Tcp)

  let connect ~cidr_v4 ?gateway_v4 ?cidr_v6 ?gateway_v6 net eth arp =
    let open Lwt.Syntax in
    let* v4 = V4.connect ~cidr:cidr_v4 ?gateway:gateway_v4 eth arp in
    let* v6 = V6.connect ?cidr:cidr_v6 ?gateway:gateway_v6 net eth in
    let* icmp = Icmp.connect v4 in
    let* ip = V4V6.connect ~ipv4_only:false ~ipv6_only:false v4 v6 in
    let* tcp = Tcp.connect ip in
    let* udp = Udp.connect ip in
    connect net eth arp ip icmp udp tcp
end
