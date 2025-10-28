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

  let encode_id (t : Int64.t) = Fmt.str "%Lx" t

  let decode_id ok rd =
    let decode t =
      try Scanf.sscanf t "%Lx" (fun x -> ok x)
      with e ->
        Endpoint.respond_error (Hsm.Bad_request, Printexc.to_string e) rd
    in
    Endpoint.lookup_path_info decode "id" rd

  let encode_member (m : Hsm.Cluster.member) =
    `Assoc
      [
        ("id", `String (encode_id m.id));
        ("name", `String m.name);
        ("peer_urls", `List (List.map (fun x -> `String x) m.peer_urls));
      ]

  let encode_member_list t =
    let items = List.map encode_member t in
    `List items

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
                Yojson.Basic.to_string (encode_member_list new_members)
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

  class handler hsm_state ip =
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
                Yojson.Basic.to_string (encode_member_list new_members)
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
                  Yojson.Basic.to_string (encode_member_list new_members)
                in
                Wm.continue true { rd with resp_body = `String body }
          in
          Json.decode Json.member_req_of_yojson content
          |> Endpoint.err_to_bad_request ok rd
        in
        decode_id ok rd
    end
end
