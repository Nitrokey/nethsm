
let requests : (Ipaddr.V4.t * string, Ptime.t list) Hashtbl.t =
  Hashtbl.create 7

let max_requests_per_second = 10

let within now ip username =
  match Hashtbl.find_opt requests (ip, username) with
  | None -> Hashtbl.add requests (ip, username) [ now ] ; true
  | Some last_requests ->
    let one_second_ago =
      let one_second = Ptime.Span.of_int_s 1 in
      match Ptime.sub_span now one_second with
      | Some ts -> ts
      | None -> Ptime.epoch (* clamped to 0 *)
    in
    let requests' = now :: List.filter (Ptime.is_later ~than:one_second_ago) last_requests in
    let result = List.length requests' <= max_requests_per_second in
    Hashtbl.replace requests (ip, username) requests';
    result

let reset ip username = Hashtbl.remove requests (ip, username)
