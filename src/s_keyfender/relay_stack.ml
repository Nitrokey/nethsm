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

  module V6 = struct
    include Ipv6.Make (Net) (Eth)
    (* TODO same than for V4 *)
  end

  module Icmp = Icmpv4.Make (V4)
  module V4V6 = Tcpip_stack_direct.IPV4V6 (V4) (V6)
  module Tcp = Tcp.Flow.Make (V4V6)
  module Udp = Udp.Make (V4V6)

  include
    Tcpip_stack_direct.MakeV4V6 (Net) (Eth) (Arp) (V4V6) (Icmp) (Udp) (Tcp)

  let connect ~cidr ?gateway net eth arp =
    let open Lwt.Syntax in
    let* v4 = V4.connect ~cidr ?gateway eth arp in
    let* v6 = V6.connect net eth in
    let* icmp = Icmp.connect v4 in
    let* ip = V4V6.connect ~ipv4_only:false ~ipv6_only:false v4 v6 in
    let* tcp = Tcp.connect ip in
    let* udp = Udp.connect ip in
    connect net eth arp ip icmp udp tcp
end
