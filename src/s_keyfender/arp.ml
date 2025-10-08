(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2016 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

module type S = sig
  type t

  val disconnect : t -> unit Lwt.t

  type error = private [> `Timeout ]

  val pp_error : error Fmt.t
  val pp : t Fmt.t
  val get_ips : t -> Ipaddr.V4.t list
  val set_ips : t -> Ipaddr.V4.t list -> unit Lwt.t
  val remove_ip : t -> Ipaddr.V4.t -> unit Lwt.t
  val add_ip : t -> Ipaddr.V4.t -> unit Lwt.t
  val query : t -> Ipaddr.V4.t -> (Macaddr.t, error) result Lwt.t
  val input : t -> Cstruct.t -> unit Lwt.t
end

open Lwt.Infix

let logsrc = Logs.Src.create "ARP" ~doc:"Mirage ARP handler"
let timeout = 40

module Make (Ethernet : Ethernet.S) = struct
  type error = [ `Timeout ]

  let pp_error ppf = function
    | `Timeout ->
        Fmt.pf ppf
          "could not determine a link-level address for the IP address given"

  type t = {
    mutable state :
      ((Macaddr.t, error) result Lwt.t * (Macaddr.t, error) result Lwt.u)
      Arp_handler.t;
    ethif : Ethernet.t;
    mutable ticking : bool;
  }

  let probe_repeat_delay =
    Duration.of_ms 1500 (* per rfc5227, 2s >= probe_repeat_delay >= 1s *)

  let output t (arp, destination) =
    let size = Arp_packet.size in
    Ethernet.write t.ethif destination `ARP ~size (fun b ->
        Arp_packet.encode_into arp b;
        size)
    >|= function
    | Ok () -> ()
    | Error e ->
        Logs.warn ~src:logsrc (fun m ->
            m "error %a while outputting packet %a to %a" Ethernet.pp_error e
              Arp_packet.pp arp Macaddr.pp destination)

  let rec tick ~probe_delay t () =
    if t.ticking then (
      Mirage_sleep.ns probe_delay >>= fun () ->
      let state, requests, timeouts = Arp_handler.tick t.state in
      t.state <- state;
      Lwt_list.iter_p (output t) requests >>= fun () ->
      List.iter (fun (_, u) -> Lwt.wakeup u (Error `Timeout)) timeouts;
      tick ~probe_delay t ())
    else Lwt.return_unit

  let pp ppf t = Arp_handler.pp ppf t.state

  let input t frame =
    let state, out, wake = Arp_handler.input t.state frame in
    t.state <- state;
    (match out with None -> Lwt.return_unit | Some pkt -> output t pkt)
    >|= fun () ->
    match wake with None -> () | Some (mac, (_, u)) -> Lwt.wakeup u (Ok mac)

  let get_ips t = Arp_handler.ips t.state

  let create ?ipaddr t =
    let mac = Arp_handler.mac t.state in
    let state, out = Arp_handler.create ~timeout ~logsrc ?ipaddr mac in
    t.state <- state;
    match out with None -> Lwt.return_unit | Some x -> output t x

  let add_ip t ipaddr =
    match Arp_handler.ips t.state with
    | [] -> create ~ipaddr t
    | _ -> (
        let state, out, wake = Arp_handler.alias t.state ipaddr in
        t.state <- state;
        output t out >|= fun () ->
        match wake with
        | None -> ()
        | Some (_, u) -> Lwt.wakeup u (Ok (Arp_handler.mac t.state)))

  let init_empty mac =
    let state, _ = Arp_handler.create ~timeout ~logsrc mac in
    state

  let set_ips t = function
    | [] ->
        let mac = Arp_handler.mac t.state in
        let state = init_empty mac in
        t.state <- state;
        Lwt.return_unit
    | ipaddr :: xs ->
        create ~ipaddr t >>= fun () -> Lwt_list.iter_s (add_ip t) xs

  let remove_ip t ip =
    let state = Arp_handler.remove t.state ip in
    t.state <- state;
    Lwt.return_unit

  let query t ip =
    let merge = function None -> Lwt.wait () | Some a -> a in
    let state, res = Arp_handler.query t.state ip merge in
    t.state <- state;
    match res with
    | Arp_handler.RequestWait (pkt, (tr, _)) -> output t pkt >>= fun () -> tr
    | Arp_handler.Wait (t, _) -> t
    | Arp_handler.Mac mac -> Lwt.return (Ok mac)

  let connect ?(probe_delay = probe_repeat_delay) ethif =
    let mac = Ethernet.mac ethif in
    let state = init_empty mac in
    let t = { ethif; state; ticking = true } in
    Lwt.async (tick ~probe_delay t);
    Lwt.return t

  let disconnect t =
    t.ticking <- false;
    Lwt.return_unit
end
