[@@@ocaml.ppx.context
  {
    tool_name = "ppx_driver";
    include_dirs = [];
    load_path = [];
    open_modules = [];
    for_package = None;
    debug = false;
    use_threads = false;
    use_vmthreads = false;
    recursive_types = false;
    principal = false;
    transparent_modules = false;
    unboxed_types = false;
    unsafe_string = false;
    cookies = [("library-name", "ocaml_protoc_plugin")]
  }]
let merge : type t v. (t, v) Spec.compound -> t -> t -> t =
  function
  | Spec.Basic (_field, _spec, default) ->
      (fun t -> fun t' -> match t' = default with | true -> t | false -> t')
  | Spec.Basic_req (_field, Message (module Message) ) -> Message.merge
  | Spec.Basic_req (_field, _spec) -> (fun _ -> fun t' -> t')
  | Spec.Basic_opt (_field, Message (module Message) ) ->
      (fun t ->
         fun t' ->
           match (t, t') with
           | (None, None) -> None
           | (Some t, None) -> Some t
           | (None, Some t) -> Some t
           | (Some t, Some t') -> Some (Message.merge t t'))
  | Spec.Basic_opt (_field, _spec) ->
      (fun t -> function | Some _ as t' -> t' | None -> t)
  | Spec.Repeated (_field, _, _) -> List.append
  | Spec.Map (_field, _) -> List.append
  | Spec.Oneof _ -> failwith "Implementation is part of generated code"
  [@@ocaml.doc
    " Merge a two values. Need to match on the spec to merge messages recursivly "]
