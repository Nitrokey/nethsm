module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) = struct

  type req_length = { length : int }[@@deriving yojson]

  module Endpoint = Endpoint.Make(Wm)(Hsm)
  module Access = Access.Make(Hsm)
  module Utils = Wm_utils.Make(Wm)(Hsm)

  class random hsm_state = object
    inherit Endpoint.base
    inherit !Endpoint.input_state_validated hsm_state [ `Operational ]
    inherit !Endpoint.role hsm_state `Operator
    inherit !Endpoint.post_json

    method private of_json json rd =
      let ok { length } =
        let data = Hsm.random length in
        let json = Yojson.Safe.to_string (`Assoc [ "random" , `String data ]) in
        Wm.respond ~body:(`String json) (Cohttp.Code.code_of_status `OK) rd
      in
      Json.to_ocaml req_length_of_yojson json |> Utils.err_to_bad_request ok rd
  end
end
