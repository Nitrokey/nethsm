open Webmachine.Rd

module Make (Wm : Webmachine.S) = struct

  class handler _now = object(self)
    inherit [Cohttp_lwt.Body.t] Wm.resource

    method private requested_key rd =
      match lookup_path_info "id" rd with
      | None -> Error `Bad_request
      | Some x -> Ok x

    method! allowed_methods rd =
      Wm.continue [`POST; `OPTIONS; `DELETE ] rd

    method! known_methods rd =
      Wm.continue [`POST; `OPTIONS; `DELETE ] rd

    method private create_key rd = 
      Wm.continue true rd

    method! delete_resource rd =
      Wm.continue true rd

    method content_types_provided rd =
      Wm.continue [ ("*/*", Wm.continue `Empty) ] rd

    method content_types_accepted rd =
      Wm.continue [
        ("application/octet-stream", self#create_key)
      ] rd

    method! is_authorized rd =
      Wm.continue `Authorized rd

    method! forbidden rd =
      Wm.continue false rd
  end

end
