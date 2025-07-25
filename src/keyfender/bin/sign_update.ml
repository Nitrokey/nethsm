(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let update_header = Bytes.of_string "_NETHSM_UPDATE_\x00"

let write_len length =
  let len_buf = Bytes.create 3 in
  assert (length < 1 lsl 24);
  (* TODO *)
  Bytes.set_uint8 len_buf 0 (length lsr 16);
  Bytes.set_uint16_be len_buf 1 (length land 0xffff);
  len_buf

let prepend_len s = Bytes.cat (write_len (Bytes.length s)) s

let read_file filename =
  let filesize = (Unix.stat filename).Unix.st_size in
  let fd = Unix.openfile filename [ Unix.O_RDONLY ] 0 in
  let buf = Bytes.create filesize in
  let rec read off =
    if off = filesize then ()
    else
      let bytes_read = Unix.read fd buf off (filesize - off) in
      read (bytes_read + off)
  in
  read 0;
  Unix.close fd;
  Bytes.to_string buf

let openssl_sign pkcs11 key_file data_file =
  let sig_file = Filename.temp_file "sig" "bin" in
  let cmd =
    match pkcs11 with
    | None ->
        Printf.sprintf "openssl dgst -sha256 -sign %s -out %s %s" key_file
          sig_file data_file
    | Some pin ->
        Printf.sprintf
          "pkcs11-tool -l --pin %s -s --id %s -m SHA256-RSA-PKCS -i %s -o %s"
          pin key_file data_file sig_file
  in
  let signature =
    if Sys.command cmd = 0 then read_file sig_file
    else invalid_arg "openssl returned non-zero exit code"
  in
  Sys.remove sig_file;
  signature

let read_file_chunked filename hash prepend_length output =
  let filesize = (Unix.stat filename).Unix.st_size in
  let hash' =
    if prepend_length then output hash @@ write_len filesize else hash
  in
  let chunksize = 4096 in
  let fd = Unix.openfile filename [ Unix.O_RDONLY ] 0 in
  let buf = Bytes.create chunksize in
  let rec read hash off =
    if off = filesize then hash
    else
      let bytes_read = Unix.read fd buf 0 (min chunksize (filesize - off)) in
      let hash' = output hash (Bytes.sub buf 0 bytes_read) in
      read hash' (bytes_read + off)
  in
  let hash'' = read hash' 0 in
  Unix.close fd;
  hash''

let sign flags key_file changelog_file version_file image_file output_file =
  let version = read_file version_file |> String.trim in
  let version_ok =
    match String.split_on_char '.' version with
    | [ major; minor ] -> (
        match (int_of_string_opt major, int_of_string_opt minor) with
        | Some _, Some _ -> true
        | _ -> false)
    | _ -> false
  in
  if not version_ok then
    invalid_arg "Version file must contain only a version number: MAJOR.MINOR";
  let data_file = Filename.temp_file "data" "bin" in
  let fd = Unix.openfile data_file [ Unix.O_WRONLY; Unix.O_CREAT ] 0 in
  let write_chunk fd () bytes =
    let written = Unix.write fd bytes 0 (Bytes.length bytes) in
    assert (written = Bytes.length bytes)
  in
  read_file_chunked changelog_file () true (write_chunk fd);
  write_chunk fd () (prepend_len (Bytes.unsafe_of_string version));
  let filesize = (Unix.stat image_file).Unix.st_size in
  let block_size = 512 in
  let blocks = (filesize + pred block_size) / block_size in
  let pad_buf =
    let padding = block_size - (filesize mod block_size) in
    if padding = block_size then Bytes.empty else Bytes.create padding
  in
  let blocks_buf =
    let l = Bytes.create 4 in
    Bytes.set_int32_be l 0 (Int32.of_int blocks);
    l
  in
  write_chunk fd () blocks_buf;
  read_file_chunked image_file () false (write_chunk fd);
  write_chunk fd () pad_buf;
  Unix.close fd;
  let signature = openssl_sign flags key_file data_file in
  Sys.remove data_file;
  let signature = prepend_len (Bytes.unsafe_of_string signature) in
  let fd =
    match output_file with
    | None -> Unix.stdout
    | Some filename ->
        if Sys.file_exists filename then
          invalid_arg "Output file already exists"
        else Unix.openfile filename [ Unix.O_WRONLY; Unix.O_CREAT ] 0o400
  in
  let write_chunk () bytes =
    let written = Unix.write fd bytes 0 (Bytes.length bytes) in
    assert (written = Bytes.length bytes)
  in
  write_chunk () @@ update_header;
  write_chunk () @@ signature;
  read_file_chunked changelog_file () true write_chunk;
  write_chunk () @@ prepend_len (Bytes.unsafe_of_string version);
  write_chunk () @@ blocks_buf;
  read_file_chunked image_file () false write_chunk;
  write_chunk () @@ pad_buf;
  Unix.close fd;
  Ok ()

open Cmdliner

let pkcs11_pin =
  let doc = "PKCS11 pin" in
  Arg.(value & opt (some string) None & info [ "pkcs11" ] ~doc ~docv:"PIN")

let key =
  let doc = "private key (or slot)" in
  Arg.(required & pos 0 (some string) None & info [] ~doc ~docv:"KEY")

let changelog =
  let doc = "changelog filename" in
  Arg.(required & pos 1 (some string) None & info [] ~doc ~docv:"CHANGES")

let version =
  let doc = "version" in
  Arg.(required & pos 2 (some string) None & info [] ~doc ~docv:"VERSION")

let image =
  let doc = "image filename" in
  Arg.(required & pos 3 (some string) None & info [] ~doc ~docv:"IMAGE")

let output =
  let doc = "output filename" in
  Arg.(value & opt (some string) None & info [ "output" ] ~doc)

let term =
  Term.(
    term_result
      (const sign $ pkcs11_pin $ key $ changelog $ version $ image $ output))

let info_ =
  let doc = "Sign a NetHSM software image" in
  let man = [ `S "BUGS"; `P "Submit bugs" ] in
  Cmd.info "sign_update" ~version:"%%VERSION_NUM%%" ~doc ~man

let () = if Cmd.(eval (v info_ term) = Exit.ok) then exit 0 else exit 1
