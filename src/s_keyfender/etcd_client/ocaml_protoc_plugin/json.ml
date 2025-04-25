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
type t =
  [ `Null  | `Bool of bool  | `Int of int  | `Float of float 
  | `String of string  | `Assoc of (string * t) list  | `List of t list ]
[@@ocaml.doc " Json type. This is identical to Yojson.Basic.t "]
let rec to_string : t -> string =
  function
  | `Null -> "null"
  | `Bool b -> string_of_bool b
  | `Int i -> string_of_int i
  | `Float f -> string_of_float f
  | `String s -> Printf.sprintf "\"%s\"" s
  | `Assoc l ->
      ((List.map
          ~f:(fun (key, value) ->
                Printf.sprintf "\"%s\": %s" key (to_string value)) l)
         |> (String.concat ~sep:", "))
        |> (Printf.sprintf "{ %s }")
  | `List l ->
      ((List.map ~f:to_string l) |> (String.concat ~sep:", ")) |>
        (Printf.sprintf "[ %s ]")
