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
open! StdLabels[@@ocaml.doc " Module for deserializing values "]
open Spec
module FieldMap = (Map.Make)(String)
type fields = Json.t FieldMap.t
let value_error type_name json =
  Result.raise (`Wrong_field_type (type_name, (Json.to_string json)))
let to_int64 =
  function
  | `String s -> Int64.of_string s
  | `Int v -> Int64.of_int v
  | json -> value_error "int64" json
let to_int json = (to_int64 json) |> Int64.to_int
let to_int32 =
  function
  | `String s -> Int32.of_string s
  | `Int v -> Int32.of_int v
  | json -> value_error "int32" json
let to_string = function | `String s -> s | json -> value_error "string" json
let to_bytes json =
  ((to_string json) |> Base64.decode_exn) |> Bytes.of_string
let to_enum : type a. (module Spec.Enum with type t = a) -> Json.t -> a =
  fun (module Enum)  ->
    function
    | `String enum -> Enum.from_string_exn enum
    | `Int enum -> Enum.from_int_exn enum
    | json -> value_error "enum" json
let to_float =
  function
  | `Float f -> f
  | `Int i -> Float.of_int i
  | `String s -> Float.of_string s
  | json -> value_error "float" json
let to_bool =
  function
  | `Bool b -> b
  | `String "true" -> true
  | `String "false" -> false
  | json -> value_error "bool" json
let to_list = function | `List l -> l | json -> value_error "list" json
let read_map : type a b.
  read_key:(string -> a) ->
    read_value:(Json.t -> b) -> Json.t -> (a * b) list
  =
  fun ~read_key ->
    fun ~read_value ->
      function
      | `Assoc entries ->
          List.map
            ~f:(fun (key, value) ->
                  let key = read_key key in
                  let value = read_value value in (key, value)) entries
      | json -> value_error "map_entry" json
let duration_of_json json =
  try
    let s = to_string json in
    assert ((s.[(String.length s) - 1]) = 's');
    (let (sign, s) =
       match (s.[0]) = '-' with
       | true -> ((-1), (String.sub s ~pos:1 ~len:((String.length s) - 2)))
       | false -> (1, (String.sub s ~pos:0 ~len:((String.length s) - 1))) in
     let (seconds, nanos) =
       match String.split_on_char ~sep:'.' s with
       | seconds::nanos::[] -> (seconds, nanos)
       | seconds::[] -> (seconds, "000")
       | _ -> failwith "Too many '.' in string" in
     let seconds = int_of_string seconds in
     let nano_fac =
       match String.length nanos with
       | 3 -> 1_000_000
       | 6 -> 1000
       | 9 -> 1
       | _ -> failwith "Nanos should be either 0, 3, 6 or 9 digits" in
     let nanos = (int_of_string nanos) * nano_fac in
     assert ((seconds >= 0) && (nanos >= 0));
     ((seconds * sign), (nanos * sign)))
  with | _ -> value_error "google.protobuf.duration" json[@@ocaml.doc
                                                           " What a strange encoding.\n    Durations less than one second are represented with a 0 seconds\n    field and a positive or negative nanos field. For durations of one\n    second or more, a non-zero value for the nanos field must be of\n    the same sign as the seconds field.\n"]
;;()
let timestamp_of_json =
  function
  | `String timestamp ->
      let t =
        match Ptime.of_rfc3339 timestamp with
        | Ok (t, _, _) -> t
        | Error _e ->
            value_error "google.protobuf.duration" (`String timestamp) in
      let seconds = (Ptime.to_float_s t) |> Int64.of_float in
      let nanos =
        (((Ptime.frac_s t) |> Ptime.Span.to_float_s) |>
           (Float.mul 1_000_000_000.0))
          |> Int64.of_float in
      (seconds, nanos)
  | json -> value_error "google.protobuf.timestamp" json
;;()
let from_camel_case s =
  let open Stdlib in
    let is_lowercase c =
      ((Char.lowercase_ascii c) = c) && ((Char.uppercase_ascii c) <> c) in
    let is_uppercase c =
      ((Char.lowercase_ascii c) <> c) && ((Char.uppercase_ascii c) = c) in
    let rec map =
      function
      | c1::c2::cs when (is_lowercase c1) && (is_uppercase c2) -> c1 :: '_'
          :: (Char.lowercase_ascii c2) :: (map cs)
      | c::cs -> c :: (map cs)
      | [] -> [] in
    ((((String.to_seq s) |> List.of_seq) |> map) |> List.to_seq) |>
      String.of_seq
;;()
let value_to_json json =
  let value =
    match json with
    | `Null -> ("nullValue", json)
    | `Float _ -> ("numberValue", json)
    | `Int _ -> ("numberValue", json)
    | `String _ -> ("stringValue", json)
    | `Bool _ -> ("boolValue", json)
    | `Assoc _ -> ("structValue", json)
    | `List _ -> ("listValue", json) in
  `Assoc [value]
let map_enum_json : (module Enum) -> Json.t -> Json.t =
  fun (module Enum)  ->
    let name =
      (((Enum.name ()) |> (String.split_on_char ~sep:'.')) |> List.tl) |>
        (String.concat ~sep:".") in
    match name with
    | "google.protobuf.NullValue" ->
        let map =
          function
          | `Null -> `String (Enum.to_string (Enum.from_int_exn 0))
          | json -> value_error name json in
        map
    | _ -> (fun json -> json)
let map_message_json : name:string -> Json.t -> Json.t =
  fun ~name ->
    match name with
    | ".google.protobuf.Empty" -> (fun json -> json)
    | ".google.protobuf.Duration" ->
        let convert json =
          let (seconds, nanos) = duration_of_json json in
          `Assoc [("seconds", (`Int seconds)); ("nanos", (`Int nanos))] in
        convert
    | ".google.protobuf.Timestamp" ->
        let convert json =
          let (seconds, nanos) = timestamp_of_json json in
          match Sys.int_size < 63 with
          | true ->
              `Assoc
                [("seconds", (`String (Int64.to_string seconds)));
                ("nanos", (`String (Int64.to_string nanos)))]
          | false ->
              `Assoc
                [("seconds", (`Int (Int64.to_int seconds)));
                ("nanos", (`Int (Int64.to_int nanos)))] in
        convert
    | ".google.protobuf.DoubleValue" | ".google.protobuf.FloatValue"
      | ".google.protobuf.Int64Value" | ".google.protobuf.UInt64Value"
      | ".google.protobuf.Int32Value" | ".google.protobuf.UInt32Value"
      | ".google.protobuf.BoolValue" | ".google.protobuf.StringValue"
      | ".google.protobuf.BytesValue" ->
        let convert json = `Assoc [("value", json)] in convert
    | ".google.protobuf.Value" -> value_to_json
    | ".google.protobuf.Struct" ->
        let convert =
          function
          | `Assoc _ as json -> `Assoc [("fields", json)]
          | json -> value_error name json in
        convert
    | ".google.protobuf.ListValue" ->
        let convert =
          function
          | `List _ as json -> `Assoc [("values", json)]
          | json -> value_error name json in
        convert
    | ".google.protobuf.FieldMask" ->
        let open StdLabels in
          let convert =
            function
            | `String s ->
                let masks =
                  ((String.split_on_char ~sep:',' s) |>
                     (List.map ~f:from_camel_case))
                    |> (List.map ~f:(fun s -> `String s)) in
                `Assoc [("paths", (`List masks))]
            | json -> value_error name json in
          convert
    | _ -> (fun json -> json)
let read_value : type a b. (a, b) spec -> Json.t -> a =
  function
  | Double -> to_float
  | Float -> to_float
  | Int32 -> to_int32
  | UInt32 -> to_int32
  | SInt32 -> to_int32
  | Fixed32 -> to_int32
  | SFixed32 -> to_int32
  | Int32_int -> to_int
  | UInt32_int -> to_int
  | SInt32_int -> to_int
  | Fixed32_int -> to_int
  | SFixed32_int -> to_int
  | UInt64 -> to_int64
  | Int64 -> to_int64
  | SInt64 -> to_int64
  | Fixed64 -> to_int64
  | SFixed64 -> to_int64
  | UInt64_int -> to_int
  | Int64_int -> to_int
  | SInt64_int -> to_int
  | Fixed64_int -> to_int
  | SFixed64_int -> to_int
  | Bool -> to_bool
  | String -> to_string
  | Bytes -> to_bytes
  | Enum (module Enum)  ->
      let map_enum_json = map_enum_json (module Enum) in
      (fun json -> (map_enum_json json) |> (to_enum (module Enum)))
  | Message (module Message)  -> Message.from_json_exn
let find_field (_number, field_name, json_name) fields =
  match FieldMap.find_opt json_name fields with
  | Some value -> Some value
  | None -> FieldMap.find_opt field_name fields
let rec read : type a b. (a, b) Spec.compound -> fields -> a =
  function
  | Basic (index, spec, default) ->
      let read_value = read_value spec in
      (fun fields ->
         match find_field index fields with
         | Some field -> read_value field
         | None -> default)
  | Basic_opt (index, spec) ->
      let read_value = read_value spec in
      (fun fields ->
         match find_field index fields with
         | Some field -> Some (read_value field)
         | None -> None)
  | Basic_req (index, spec) ->
      let read_value = read_value spec in
      (fun fields ->
         match find_field index fields with
         | Some field -> read_value field
         | None -> Result.raise (`Required_field_missing (0, "")))
  | Repeated (index, spec, _packed) ->
      let read = read_value spec in
      (fun fields ->
         match find_field index fields with
         | Some field -> (to_list field) |> (List.map ~f:read)
         | None -> [])
  | Map (index, (key_spec, Basic (_, value_spec, _))) ->
      let read_key = read_value key_spec in
      let read_key v = read_key (`String v) in
      let read_value = read_value value_spec in
      (fun fields ->
         match find_field index fields with
         | Some field -> read_map ~read_key ~read_value field
         | None -> [])
  | Map (index, (key_spec, Basic_opt (_, value_spec))) ->
      let read_key = read_value key_spec in
      let read_key v = read_key (`String v) in
      let read_value = read_value value_spec in
      let read_value =
        function
        | `Null -> (try Some (read_value `Null) with | _ -> None)
        | json -> Some (read_value json) in
      (fun fields ->
         match find_field index fields with
         | Some field -> read_map ~read_key ~read_value field
         | None -> [])
  | Oneof (oneofs, _) ->
      let rec make_readers =
        function
        | (Oneof_elem (index, spec, (constr, _)))::rest ->
            let read = read (Spec.Basic_opt (index, spec)) in
            let read_opt fields =
              match read fields with
              | Some v -> Some (constr v)
              | None -> None in
            read_opt :: (make_readers rest)
        | [] -> [] in
      let readers = make_readers oneofs in
      let rec find fields =
        function
        | [] -> `not_set
        | read_opt::rest ->
            (match read_opt fields with
             | Some v -> v
             | None -> find fields rest) in
      (fun fields -> find fields readers)
let rec deserialize : type constr a.
  (constr, a) compound_list -> constr -> fields -> a =
  function
  | Nil -> (fun constr -> fun _json -> constr)
  | Nil_ext _extension_ranges -> (fun constr -> fun _json -> constr [])
  | Cons (spec, rest) ->
      let read = read spec in
      let cont = deserialize rest in
      (fun constr ->
         fun fields -> let v = read fields in cont (constr v) fields)
let deserialize : type constr a.
  message_name:string -> (constr, a) compound_list -> constr -> Json.t -> a =
  fun ~message_name ->
    fun spec ->
      fun constr ->
        let deserialize = deserialize spec constr in
        let map_message = map_message_json ~name:message_name in
        fun json ->
          match map_message json with
          | `Assoc fields ->
              (fields |>
                 (List.fold_left
                    ~f:(fun map ->
                          fun (key, value) -> FieldMap.add key value map)
                    ~init:FieldMap.empty))
                |> deserialize
          | json -> value_error "message" json
