(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Syntax

(*
  A reconfigurable stack is a network stack whose IP is decided at runtime.
  As such, `connect` only prepare the stack's state, but it can only be considered
  ready when `setup` is called. *)
module type S = sig
  type t

  val setup : t -> ?gateway:Ipaddr.V4.t -> Ipaddr.V4.Prefix.t -> unit Lwt.t
  val disconnect : t -> unit Lwt.t

  module Stack : Tcpip.Stack.V4V6

  val stack : t -> Stack.t
end

module Direct
    (Net : Mirage_net.S)
    (Eth : Ethernet.S)
    (Arp : Arp.S) : sig
  include S

  val connect : Net.t -> Eth.t -> Arp.t -> t Lwt.t
end = struct
  module Ipv4 = Static_ipv4.Make (Eth) (Arp)
  module Ipv6 = Ipv6.Make (Net) (Eth)
  module Icmp = Icmpv4.Make (Ipv4)
  module Ip = Tcpip_stack_direct.IPV4V6 (Ipv4) (Ipv6)
  module Udp = Udp.Make (Ip)
  module Tcp = Tcp.Flow.Make (Ip)

  module Stack =
    Tcpip_stack_direct.MakeV4V6 (Net) (Eth) (Arp) (Ip) (Icmp) (Udp)
      (Tcp)

  type net = Net.t
  type eth = Eth.t
  type arp = Arp.t
  type network = { net : net; eth : eth; arp : arp }
  type state = Unconfigured | Ready of { tcp : Tcp.t; stack : Stack.t }
  type t = network * state ref

  let connect net eth arp = Lwt.return ({ net; eth; arp }, ref Unconfigured)

  let setup ({ net; eth; arp }, state) ?gateway cidr =
    match !state with
    | Ready _ ->
        Fmt.invalid_arg "Stack is already configured. Call disconnect first."
    | Unconfigured ->
        let* ipv4 = Ipv4.connect ~cidr ?gateway eth arp in
        let* icmp = Icmp.connect ipv4 in
        let* ipv6 = Ipv6.connect ~no_init:true ~handle_ra:false net eth in
        let* ip = Ip.connect ~ipv4_only:true ~ipv6_only:false ipv4 ipv6 in
        let* udp = Udp.connect ip in
        let* tcp = Tcp.connect ip in
        let+ stack = Stack.connect net eth arp ip icmp udp tcp in
        state := Ready { tcp; stack }

  let disconnect (_, state) =
    match !state with
    | Unconfigured -> Fmt.invalid_arg "Cannot disconnect an unconfigured stack."
    | Ready { tcp; stack } ->
        let* () = Tcp.disconnect tcp in
        let+ () = Stack.disconnect stack in
        state := Unconfigured

  let stack (_, state) =
    match !state with
    | Unconfigured -> Fmt.invalid_arg "Stack is not configured."
    | Ready { stack; _ } -> stack
end

module Fixed (Stack : Tcpip.Stack.V4V6) : sig
  include S with module Stack = Stack

  val connect : Stack.t -> t Lwt.t
end = struct
  type t = Stack.t

  let connect = Lwt.return

  let disconnect _ =
    Logs.warn (fun f -> f "This stack is not configurable.");
    Lwt.return_unit

  let setup _ ?gateway:_ _ =
    Logs.warn (fun f -> f "This stack is not configurable.");
    Lwt.return_unit

  let stack = Fun.id

  module Stack = Stack
end
