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

  class handler_namespaces hsm_state ip =
    object
      inherit common hsm_state ip
      inherit Endpoint.get_json

      method private to_json rd =
        Hsm.Namespace.list hsm_state >>= function
        | Ok xs ->
            let items =
              List.map (fun name -> `Assoc [ ("id", `String name) ]) xs
            in
            let body = Yojson.Safe.to_string (`List items) in
            Wm.continue (`String body) rd
        | Error e -> Endpoint.respond_error e rd
    end

  class handler hsm_state ip =
    object (self)
      inherit common hsm_state ip
      method! allowed_methods rd = Wm.continue [ `PUT; `DELETE ] rd

      method! resource_exists rd =
        let ok id =
          Hsm.Namespace.exists hsm_state (Some id) >>= function
          | Ok does_exist -> Wm.continue does_exist rd
          | Error e -> Endpoint.respond_error e rd
        in
        Endpoint.lookup_path_info ok "id" rd

      method! delete_resource rd =
        let ok id =
          Hsm.Namespace.remove hsm_state (Some id) >>= function
          | Error e -> Endpoint.respond_error e rd
          | Ok () -> (
              Hsm.Key.remove_all_in_namespace hsm_state ~namespace:id
              >>= function
              | Ok () -> Wm.continue true rd
              | Error e -> Endpoint.respond_error e rd)
        in
        Endpoint.lookup_path_info ok "id" rd

      method content_types_provided rd =
        Wm.continue [ ("application/json", Wm.continue `Empty) ] rd

      method content_types_accepted rd =
        Wm.continue
          [
            ("application/json", self#put_resource);
            ("application/octet-stream", self#put_resource);
          ]
          rd

      method private put_resource rd =
        let ok id =
          match Json.valid_namespace (Some id) with
          | Error msg -> Endpoint.respond_error (Bad_request, msg) rd
          | Ok () -> (
              Hsm.Namespace.create hsm_state (Some id) >>= function
              | Error e -> Endpoint.respond_error e rd
              | Ok () -> Wm.continue true rd)
        in
        Endpoint.lookup_path_info ok "id" rd
    end
end
