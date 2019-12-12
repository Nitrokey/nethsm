open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  type req_length = { length : int }[@@deriving yojson]

  module Endpoint = Endpoint.Make(Wm)(Hsm)
  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class random hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok { length } =
        let data = Hsm.random length in
        let json = Yojson.Safe.to_string (`Assoc [ "random" , `String data ]) in
        Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd
      in
      Json.to_ocaml req_length_of_yojson json |> Utils.err_to_bad_request ok rd

    method! is_authorized rd =
      Access.is_authorized hsm_state rd >>= fun (auth, rd') ->
      Wm.continue auth rd'

    method! forbidden rd =
      Access.forbidden hsm_state `Operator rd >>= fun auth ->
      Wm.continue auth rd
  end
end
