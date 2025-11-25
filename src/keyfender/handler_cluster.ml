open Lwt.Infix

module Make (Wm : Webmachine.S with type +'a io = 'a Lwt.t) (Hsm : Hsm.S) =
struct
  module Endpoint = Endpoint.Make (Wm) (Hsm)

  class virtual common hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
    end

  let encode_id (t : Int64.t) = `String (Fmt.str "%Lx" t)

  let decode_id' t =
    try Scanf.sscanf t "%Lx" (fun x -> Ok x)
    with e -> Error (Printexc.to_string e)

  let decode_id ok rd =
    let decode t =
      match decode_id' t with
      | Ok id -> ok id
      | Error e -> Endpoint.respond_error (Hsm.Bad_request, e) rd
    in
    Endpoint.lookup_path_info decode "id" rd

  let decode_id_yojson t =
    let id = Yojson.Safe.to_string t in
    decode_id' id

  type member = Hsm.Cluster.member = {
    id : int64; [@to_yojson encode_id] [@of_yojson decode_id_yojson]
    name : string;
    peer_urls : string list;
  }
  [@@deriving yojson]

  let encode_member_list = [%to_yojson: member list]

  class handler_members hsm_state ip =
    object (self)
      inherit common hsm_state ip
      method! allowed_methods rd = Wm.continue [ `GET; `POST ] rd

      method private list_members rd =
        Hsm.Cluster.member_list hsm_state >>= function
        | Ok xs ->
            let body = Yojson.Safe.to_string (encode_member_list xs) in
            Wm.continue (`String body) rd
        | Error e -> Endpoint.respond_error e rd

      method private add_member rd =
        let body = rd.Webmachine.Rd.req_body in
        Cohttp_lwt.Body.to_string body >>= fun content ->
        let ok (member_req : Json.member_req) =
          let peer_urls = member_req.peer_urls in
          Hsm.Cluster.member_add ~peer_urls hsm_state >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok new_members ->
              let body =
                Yojson.Safe.to_string (encode_member_list new_members)
              in
              Wm.continue true { rd with resp_body = `String body }
        in
        Json.decode Json.member_req_of_yojson content
        |> Endpoint.err_to_bad_request ok rd

      method! post_is_create rd = Wm.continue true rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", self#list_members) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#add_member) ] rd
    end

  class handler_join hsm_state ip =
    object
      inherit Endpoint.base_with_body_length
      inherit! Endpoint.input_state_validated hsm_state [ `Operational ]
      inherit! Endpoint.r_role hsm_state `Administrator ip
      inherit! Endpoint.post_json
      inherit! Endpoint.no_cache

      method private of_json json rd =
        let ok join_req =
          Hsm.System.join_cluster hsm_state join_req >>= function
          | Ok () -> Wm.continue true rd
          | Error e -> Endpoint.respond_error e rd
        in
        Json.join_req_of_yojson json |> Endpoint.err_to_bad_request ok rd
    end

  class handler_member hsm_state ip =
    object (self)
      inherit common hsm_state ip
      method! allowed_methods rd = Wm.continue [ `PUT; `DELETE ] rd

      method! resource_exists rd =
        let ok id =
          Hsm.Cluster.member_exists ~id hsm_state >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        decode_id ok rd

      method! delete_resource rd =
        let ok id =
          Hsm.Cluster.member_remove ~id hsm_state >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok new_members ->
              let body =
                Yojson.Safe.to_string (encode_member_list new_members)
              in
              Wm.continue true { rd with resp_body = `String body }
        in
        decode_id ok rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue [ ("application/json", self#put_resource) ] rd

      method private put_resource rd =
        let ok id =
          let body = rd.Webmachine.Rd.req_body in
          Cohttp_lwt.Body.to_string body >>= fun content ->
          let ok (member_req : Json.member_req) =
            let peer_urls = member_req.peer_urls in
            Hsm.Cluster.member_update ~id ~peer_urls hsm_state >>= function
            | Error e -> Endpoint.respond_error e rd
            | Ok new_members ->
                let body =
                  Yojson.Safe.to_string (encode_member_list new_members)
                in
                Wm.continue true { rd with resp_body = `String body }
          in
          Json.decode Json.member_req_of_yojson content
          |> Endpoint.err_to_bad_request ok rd
        in
        decode_id ok rd
    end
end
