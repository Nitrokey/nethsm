
let requests : (Ipaddr.V4.t * string, Ptime.t list) Hashtbl.t =
  Hashtbl.create 7

let one_second_ago now =
  let one_second = Ptime.Span.of_int_s 1 in
  match Ptime.sub_span now one_second with
  | Some ts -> ts
  | None -> Ptime.epoch (* clamped to 0 *)

let active_requests than reqs =
  List.filter (Ptime.is_later ~than) reqs

let within now ip username =
  match Hashtbl.find_opt requests (ip, username) with
  | None -> Hashtbl.add requests (ip, username) [ now ] ; true
  | Some last_requests ->
    let requests' = now :: active_requests (one_second_ago now) last_requests in
    let result = List.length requests' <= 1 in
    Hashtbl.replace requests (ip, username) requests';
    result

let reset ip username = Hashtbl.remove requests (ip, username)

let discard_old_entries now =
  let valid = one_second_ago now in
  Hashtbl.filter_map_inplace
    (fun _ vs -> match active_requests valid vs with [] -> None | xs -> Some xs)
    requests

let reset_all () =
  Hashtbl.reset requests
