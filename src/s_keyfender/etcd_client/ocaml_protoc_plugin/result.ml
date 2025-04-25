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
type error =
  [ `Premature_end_of_input  | `Unknown_field_type of int 
  | `Wrong_field_type of (string * string) 
  | `Illegal_value of (string * Field.t)  | `Unknown_enum_value of int 
  | `Unknown_enum_name of string 
  | `Required_field_missing of (int * string) ]
exception Error of error 
type 'a t = ('a, error) result
let raise error = raise (Error error)
let catch f = try Ok (f ()) with | Error (#error as v) -> Error v
let (>>|) : 'a t -> ('a -> 'b) -> 'b t =
  function | Ok x -> (fun f -> Ok (f x)) | Error err -> (fun _ -> Error err)
let (>>=) : 'a t -> ('a -> 'b t) -> 'b t =
  function | Ok x -> (fun f -> f x) | Error err -> (fun _ -> Error err)
let return x = Ok x
let fail : error -> 'a t = fun x -> Error x
let get ~msg  = function | Ok v -> v | Error _ -> failwith msg
let pp_error : Format.formatter -> [> error] -> unit =
  fun fmt ->
    function
    | `Premature_end_of_input ->
        Format.pp_print_string fmt "`Premature_end_of_input"
    | `Unknown_field_type x ->
        (Format.fprintf fmt "`Unknown_field_type (@[<hov>";
         (Format.fprintf fmt "%d") x;
         Format.fprintf fmt "@])")
    | `Wrong_field_type x ->
        (Format.fprintf fmt "`Wrong_field_type (@[<hov>";
         ((fun (a0, a1) ->
             Format.fprintf fmt "(@[";
             ((Format.fprintf fmt "%S") a0;
              Format.fprintf fmt ",@ ";
              (Format.fprintf fmt "%S") a1);
             Format.fprintf fmt "@])")) x;
         Format.fprintf fmt "@])")
    | `Illegal_value x ->
        (Format.fprintf fmt "`Illegal_value (@[<hov>";
         ((fun (a0, a1) ->
             Format.fprintf fmt "(@[";
             ((Format.fprintf fmt "%S") a0;
              Format.fprintf fmt ",@ ";
              (Field.pp fmt) a1);
             Format.fprintf fmt "@])")) x;
         Format.fprintf fmt "@])")
    | `Unknown_enum_value x ->
        (Format.fprintf fmt "`Unknown_enum_value (@[<hov>";
         (Format.fprintf fmt "%d") x;
         Format.fprintf fmt "@])")
    | `Unknown_enum_name x ->
        (Format.fprintf fmt "`Unknown_enum_name (@[<hov>";
         (Format.fprintf fmt "%s") x;
         Format.fprintf fmt "@])")
    | `Oneof_missing -> Format.pp_print_string fmt "`Oneof_missing"
    | `Required_field_missing x ->
        (Format.fprintf fmt "`Required_field_missing (@[<hov>";
         ((fun (a0, a1) ->
             Format.fprintf fmt "(@[";
             ((Format.fprintf fmt "%d") a0;
              Format.fprintf fmt ",@ ";
              (Format.fprintf fmt "%s") a1);
             Format.fprintf fmt "@])")) x;
         Format.fprintf fmt "@])")
let show_error : error -> string = Format.asprintf "%a" pp_error
let _ =
  Printexc.register_printer
    (function
     | Error e ->
         (Printf.sprintf "Ocaml_protoc_plugin.Result.Error (%s)"
            (show_error e))
           |> Option.some
     | _ -> None)
let pp pp fmt =
  function
  | Ok v -> Format.fprintf fmt "Ok %a" pp v
  | Error (#error as e) -> Format.fprintf fmt "Error %a" pp_error e
