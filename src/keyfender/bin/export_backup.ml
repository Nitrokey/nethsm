(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Keyfender

let read_file filename =
  let filesize = (Unix.stat filename).Unix.st_size in
  let fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
  let buf = Bytes.create filesize in
  let rec read off =
    if off = filesize
    then ()
    else
      let bytes_read = Unix.read fd buf off (filesize - off) in
      read (bytes_read + off)
  in
  read 0;
  Unix.close fd;
  Bytes.to_string buf

(*
let read_file_chunked filename hash prepend_length output =
  let filesize = (Unix.stat filename).Unix.st_size in
  let hash' =
    if prepend_length
    then output hash @@ Bytes.of_string @@ write_len filesize
    else hash
  in
  let chunksize = 4096 in
  let fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
  let buf = Bytes.create chunksize in
  let rec read hash off =
    if off = filesize
    then hash
    else
      let bytes_read = Unix.read fd buf 0 (min chunksize (filesize - off)) in
      let hash' = output hash (Bytes.sub buf 0 bytes_read) in
      read hash' (bytes_read + off)
  in
  let hash'' = read hash' 0 in
  Unix.close fd;
  hash''
*)

(*
let read_n stream n =
  let rec read prefix =
    let open Lwt.Infix in
    Lwt_stream.get stream >>= function
    | None -> Lwt.return @@ Error (Bad_request, "Malformed update")
    | Some data ->
      let str = prefix ^ data in
      if String.length str >= n
      then
        let data, rest = Astring.String.span ~min:n ~max:n str in
        Lwt.return @@ Ok (data, put_back stream rest)
      else read str
  in
  read ""
*)

let decode_length data =
  let data' = Cstruct.of_string data in
  let byte = Cstruct.get_uint8 data' 0 in
  let len = Cstruct.BE.get_uint16 data' 1 in
  byte lsl 16 + len

(*
let get_length stream =
  let open Lwt_result.Infix in
  read_n stream 3 >|= fun (data, stream') ->
  let length = decode_length data in
  (length, stream')

let get_data (l, s) = read_n s l
*)

let get_field s =
  let len = decode_length s in
  let offset = 3 + len in
  String.sub s 3 len, String.sub s offset (String.length s - offset)

let version = "0"

let err_to_msg = function
  | Error e -> Error (`Msg e)
  | Ok a -> Ok a

let decrypt ~key ~adata data =
  match Crypto.decrypt ~key ~adata (Cstruct.of_string data) with
  | Error `Insufficient_data ->
    Error ("Could not decrypt stored " ^ (Cstruct.to_string adata) ^ ". Backup is corrupted?")
  | Error `Not_authenticated ->
    Error ("Could not decrypt stored " ^ (Cstruct.to_string adata) ^ ". Authentication failed midway. Backup is corrupted?")
  | Ok x -> Ok x

let backup_header = "_NETHSM_BACKUP_"
let backup_version_v0 = Char.chr 0

let export passphrase backup_image_filename output =
  let (let*) = Result.bind in
  err_to_msg @@
  let backup_data = read_file backup_image_filename in
  let header_len = String.length backup_header in
  let header = String.sub backup_data 0 header_len in
  let version = String.get backup_data header_len in
  let backup_data = String.(sub backup_data (header_len+1) (length backup_data - header_len - 1)) in
  let* () =
    if String.(equal (sub header 0 (length backup_header)) backup_header) then
      Ok ()
    else
      Error "Not a NetHSM backup file"
  in
  let* () =
    match version with
    | x when x = backup_version_v0 -> Ok ()
    | _ ->
      let msg =
        Printf.sprintf
          "Version mismatch on restore, provided backup version is %d, server expects %d"
          (Char.code version) (Char.code backup_version_v0)
      in
      Error msg
  in
  let salt, backup_data = get_field backup_data in
  let backup_key =
    Crypto.key_of_passphrase ~salt:(Cstruct.of_string salt) passphrase
  in
  let key = Crypto.GCM.of_secret backup_key in
  let encrypted_version, backup_data = get_field backup_data in
  let adata = Cstruct.of_string "backup-version" in
  let* version_int = decrypt ~key ~adata encrypted_version in
  let* () = if version = (Cstruct.get_char version_int 0) then
      Ok ()
    else
      Error "Internal and external version mismatch."
  in
  let encrypted_domain_key, backup_data = get_field backup_data in
  let adata = Cstruct.of_string "domain-key" in
  let* locked_domain_key = decrypt ~key ~adata encrypted_domain_key in
  let rec next acc rest =
    if rest = "" then Ok acc else
    let item, rest = get_field rest in
    let adata = Cstruct.of_string "backup" in
    let* key_value_pair = decrypt ~key ~adata item in
    let key, value = get_field (Cstruct.to_string key_value_pair) in
    next ((key, value) :: acc) rest
  in
  let init = [".locked-domain-key", Cstruct.to_string locked_domain_key] in
  match next init backup_data with
  | Error e -> Error e
  | Ok kvs ->
    let fd = match output with
      | None -> Unix.stdout
      | Some filename ->
        if Sys.file_exists filename
        then invalid_arg "Output file already exists"
        else Unix.openfile filename [Unix.O_WRONLY ; Unix.O_CREAT] 0o400
    in
    let channel = Unix.out_channel_of_descr fd in
    let json = `Assoc (List.rev_map (fun (k, v) -> k, `String (Base64.encode_string v)) kvs) in
    Yojson.Basic.pretty_to_channel channel json;
    Unix.close fd;
    Ok ()

open Cmdliner

let key =
  let doc = "backup-passphrase" in
  Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"KEY")

let backup_image =
  let doc = "backup image filename" in
  Arg.(required & pos 1 (some string) None & info [] ~doc ~docv:"IMAGE")

let output =
  let doc = "output filename" in
  Arg.(value & opt (some string) None & info [ "output" ] ~doc)

let command =
  let doc = "Export a NetHSM backup image to json" in
  let man = [ `S "BUGS"; `P "Submit bugs";] in
  Term.(term_result (const export $ key $ backup_image $ output)),
  Term.info "export_backup" ~version:"%%VERSION_NUM%%" ~doc ~man

let () =
  Mirage_crypto_rng_unix.initialize ();
  match Term.eval command with `Ok () -> exit 0 | _ -> exit 1
