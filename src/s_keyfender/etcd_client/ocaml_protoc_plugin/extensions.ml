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
open StdLabels
type t = (int * Field.t) list
let default = []
let pp_item fmt (index, field) =
  Format.fprintf fmt "(%d, %a)" index Field.pp field
let pp : Format.formatter -> t -> unit =
  fun fmt -> Format.pp_print_list pp_item fmt
let show : t -> string = Format.asprintf "%a" pp
let equal _ _ = true
let compare _ _ = 0
let index_of_spec : type a b. (a, b) Spec.compound -> int =
  function
  | Basic ((index, _, _), _, _) -> index
  | Basic_opt ((index, _, _), _) -> index
  | Basic_req ((index, _, _), _) -> index
  | Repeated ((index, _, _), _, _) -> index
  | Map ((index, _, _), _) -> index
  | Oneof _ -> failwith "Oneof fields not allowed in extensions"
let get : type a b. (a, b) Spec.compound -> t -> a =
  fun spec ->
    fun t ->
      let writer = Writer.of_list t in
      let reader = (Writer.contents writer) |> Reader.create in
      Deserialize.deserialize (let open Spec in Cons (spec, Nil))
        (fun a -> a) reader
let set : type a b. (a, b) Spec.compound -> t -> a -> t =
  fun spec ->
    fun t ->
      fun v ->
        let writer = Writer.init () in
        Serialize.serialize (let open Spec in Cons (spec, Nil)) writer v;
        (let index = index_of_spec spec in
         let fields =
           ((Writer.contents writer) |> Reader.create) |> Reader.to_list in
         (List.filter ~f:(fun (i, _) -> i != index) t) @ fields)
