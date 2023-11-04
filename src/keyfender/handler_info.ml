(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class info hsm_state =
    object (self)
      inherit Endpoint.base_with_body_length
      inherit Endpoint.get_json

      method private to_json =
        let json =
          Hsm.info hsm_state |> Json.info_to_yojson |> Yojson.Safe.to_string
        in
        Wm.continue (`String json)

      method! generate_etag rd =
        self#to_json rd >>= function
        | Ok (`String json), _ ->
            let etag = Digest.to_hex (Digest.string json) in
            Wm.continue (Some etag) rd
        | _ -> Wm.continue None rd
    end
end
