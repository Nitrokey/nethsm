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
open StdLabels[@@ocaml.doc
                " Some buffer to hold data, and to read and write data "]
open Field
let length_delimited_size_field_length = 5
type substring = {
  mutable offset: int ;
  buffer: Bytes.t }
type mode =
  | Balanced 
  | Speed 
  | Space 
type t = {
  mutable data: substring list ;
  mode: mode ;
  block_size: int }
let init ?(mode= Space)  ?(block_size= 120)  () =
  { data = []; mode; block_size }
let size t =
  let rec inner acc =
    function | [] -> acc | { offset;_}::tl -> inner (offset + acc) tl in
  inner 0 t.data
let unused_space t =
  let rec inner acc =
    function
    | { offset; buffer }::xs ->
        inner (((Bytes.length buffer) - offset) + acc) xs
    | [] -> acc in
  inner 0 t.data
let write_varint buffer ~offset  v =
  let rec inner ~offset  v =
    let next_offset = offset + 1 in
    let open Infix.Int64 in
      match v lsr 7 with
      | 0L ->
          (Bytes.unsafe_set buffer offset
             ((Int64.to_int v) |> Char.unsafe_chr);
           next_offset)
      | rem ->
          (Bytes.unsafe_set buffer offset
             ((((v land 0x7fL) lor 0b1000_0000L) |> Int64.to_int) |>
                Char.unsafe_chr);
           inner ~offset:next_offset rem) in
  inner ~offset v
let write_varint_unboxed buffer ~offset  v =
  write_varint buffer ~offset (Int64.of_int v)
let write_delimited_field_length_fixed_size buffer ~offset  v =
  let vl = Int64.of_int v in
  let offset =
    write_varint buffer ~offset (let open Int64 in logor vl 0x400000000L) in
  let v = Bytes.get_uint8 buffer (offset - 1) in
  Bytes.set_uint8 buffer (offset - 1) (v land 0b0011_1111); offset[@@ocaml.doc
                                                                    " Write a field delimited length.\n    A delimited field length can be no larger than 2^31.\n    This function always write 5 bytes (7*5bits = 35bits > 31bits).\n    This allows the field length to be statically allocated and written later.\n    The spec does not forbid this encoding, but there might be implementation\n    that disallow '0' as the ending varint value.\n"]
let ensure_capacity ~size  t =
  match t.data with
  | ({ offset; buffer } as elem)::_ when
      ((Bytes.length buffer) - offset) >= size -> elem
  | tl ->
      let elem =
        { offset = 0; buffer = (Bytes.create (max size t.block_size)) } in
      (t.data <- (elem :: tl); elem)
let write_const_value data t =
  let len = String.length data in
  let elem = ensure_capacity ~size:len t in
  Bytes.blit_string ~src:data ~src_pos:0 ~dst:(elem.buffer)
    ~dst_pos:(elem.offset) ~len;
  elem.offset <- (elem.offset + len)[@@ocaml.doc " Direct functions "]
let write_fixed32_value : int32 -> t -> unit =
  fun v ->
    fun t ->
      let elem = ensure_capacity ~size:4 t in
      Bytes.set_int32_le elem.buffer elem.offset v;
      elem.offset <- (elem.offset + 4)
let write_fixed64_value : int64 -> t -> unit =
  fun v ->
    fun t ->
      let elem = ensure_capacity ~size:8 t in
      Bytes.set_int64_le elem.buffer elem.offset v;
      elem.offset <- (elem.offset + 8)
let write_varint_unboxed_value : int -> t -> unit =
  fun v ->
    fun t ->
      let elem = ensure_capacity ~size:10 t in
      let offset = write_varint_unboxed elem.buffer ~offset:(elem.offset) v in
      elem.offset <- offset
let write_varint_value : int64 -> t -> unit =
  fun v ->
    fun t ->
      let elem = ensure_capacity ~size:10 t in
      let offset = write_varint elem.buffer ~offset:(elem.offset) v in
      elem.offset <- offset
let write_length_delimited_value
  : data:string -> offset:int -> len:int -> t -> unit =
  fun ~data ->
    fun ~offset ->
      fun ~len ->
        fun t ->
          write_varint_unboxed_value len t;
          (let elem = ensure_capacity ~size:len t in
           Bytes.blit_string ~src:data ~src_pos:offset ~dst:(elem.buffer)
             ~dst_pos:(elem.offset) ~len;
           elem.offset <- (elem.offset + len))
let write_field_header : t -> int -> int -> unit =
  fun t ->
    fun index ->
      fun field_type ->
        let header = (index lsl 3) + field_type in
        write_varint_unboxed_value header t
let write_field : t -> int -> Field.t -> unit =
  fun t ->
    fun index ->
      fun field ->
        let (field_type, writer) =
          match field with
          | Varint v -> (0, (write_varint_value v))
          | Varint_unboxed v -> (0, (write_varint_unboxed_value v))
          | Fixed_64_bit v -> (1, (write_fixed64_value v))
          | Length_delimited { offset; length; data } ->
              (2, (write_length_delimited_value ~data ~offset ~len:length))
          | Fixed_32_bit v -> (5, (write_fixed32_value v)) in
        write_field_header t index field_type; writer t
let write_length_delimited_f ~write_f  v t =
  let rec size_data_added sentinel acc =
    function
    | [] -> failwith "End of list reached. This is impossible"
    | x::_ when x == sentinel -> acc
    | { offset;_}::xs -> size_data_added sentinel (offset + acc) xs in
  let write_balanced v t =
    let sentinel =
      match t.data with
      | ({ offset; buffer } as sentinel)::_ when
          (offset + length_delimited_size_field_length) <=
            (Bytes.length buffer)
          -> sentinel
      | _ ->
          let sentinel =
            {
              offset = 0;
              buffer = (Bytes.create length_delimited_size_field_length)
            } in
          (t.data <- (sentinel :: (t.data)); sentinel) in
    let offset = sentinel.offset in
    sentinel.offset <- Int.max_int;
    (let () = write_f t v in
     let size = size_data_added sentinel 0 t.data in
     let offset = write_varint_unboxed sentinel.buffer ~offset size in
     sentinel.offset <- offset; ()) in
  let write_speed v t =
    let sentinel = ensure_capacity ~size:length_delimited_size_field_length t in
    let offset = sentinel.offset in
    sentinel.offset <- (sentinel.offset + length_delimited_size_field_length);
    (let () = write_f t v in
     let size =
       size_data_added sentinel
         (sentinel.offset - (offset + length_delimited_size_field_length))
         t.data in
     let _ =
       write_delimited_field_length_fixed_size sentinel.buffer ~offset size in
     ()) in
  let write_space v t =
    let sentinel = ensure_capacity ~size:length_delimited_size_field_length t in
    let offset = sentinel.offset in
    sentinel.offset <- (sentinel.offset + length_delimited_size_field_length);
    (let () = write_f t v in
     let size =
       size_data_added sentinel
         (sentinel.offset - (offset + length_delimited_size_field_length))
         t.data in
     let offset' = write_varint_unboxed sentinel.buffer ~offset size in
     let () =
       match (offset + length_delimited_size_field_length) = offset' with
       | true -> ()
       | false ->
           (Bytes.blit ~src:(sentinel.buffer)
              ~src_pos:(offset + length_delimited_size_field_length)
              ~dst:(sentinel.buffer) ~dst_pos:offset'
              ~len:(sentinel.offset -
                      (offset + length_delimited_size_field_length));
            sentinel.offset <-
              (sentinel.offset -
                 ((offset + length_delimited_size_field_length) - offset'))) in
     ()) in
  match t.mode with
  | Balanced -> write_balanced v t
  | Speed -> write_speed v t
  | Space -> write_space v t
let contents t =
  let size = size t in
  let contents = Bytes.create size in
  let rec inner offset =
    function
    | [] -> offset
    | { offset = o; buffer }::tl ->
        let next_offset = offset - o in
        (Bytes.blit ~src:buffer ~src_pos:0 ~dst:contents ~dst_pos:next_offset
           ~len:o;
         inner next_offset tl) in
  let offset = inner size t.data in
  assert (offset = 0); Bytes.unsafe_to_string contents
let dump t =
  let string_contents = contents t in
  ((List.init ~len:(String.length string_contents)
      ~f:(fun i -> Printf.sprintf "%02x" (Char.code (string_contents.[i]))))
     |> (String.concat ~sep:"-"))
    |> (Printf.printf "Buffer: %s\n")
let string_of_bytes b =
  ((((Bytes.to_seq b) |> (Seq.map Char.code)) |>
      (Seq.map (Printf.sprintf "%02x")))
     |> List.of_seq)
    |> (String.concat ~sep:" ")
let of_list : (int * Field.t) list -> t =
  fun fields ->
    let t = init () in
    List.iter ~f:(fun (index, field) -> write_field t index field) fields; t
;;()
;;()
;;()
