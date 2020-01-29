open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  module Endpoint = Endpoint.Make(Wm)(Hsm)

  let last_requests = ref []

  (* TODO store in configuration *)
  let max_requests_per_second = 100

  let within_rate_limit _hsm_state =
    let one_second_ago =
      let one_second = Ptime.Span.of_int_s 1 in
      match Ptime.sub_span (Hsm.now ()) one_second with
      | Some ts -> ts
      | None -> assert false
    in
    last_requests := List.filter (Ptime.is_later ~than:one_second_ago) !last_requests;
    let result = List.length !last_requests <= max_requests_per_second in
    last_requests := Hsm.now () :: !last_requests;
    result

  class unlock hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Locked ] as super
    inherit !Endpoint.put_json
    inherit !Endpoint.no_cache

    method !service_available : (bool, Cohttp_lwt.Body.t) Wm.op =
      if within_rate_limit hsm_state
      then super#service_available
      else Wm.respond (Cohttp.Code.code_of_status `Too_many_requests)

    method private of_json json rd =
      let ok passphrase =
        Hsm.unlock_with_passphrase hsm_state ~passphrase >>= function
        | Ok () -> Wm.continue true rd
        | Error e -> Endpoint.respond_error e rd
      in
      Json.decode_passphrase json |> Endpoint.err_to_bad_request ok rd
  end
end
