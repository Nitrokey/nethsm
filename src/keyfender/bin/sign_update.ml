(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

module Hash = Mirage_crypto.Hash.SHA256

let write_len length =
  let len_buf = Cstruct.create 3 in
  assert (length < 1 lsl 24); (* TODO *)
  Cstruct.set_uint8 len_buf 0 (length lsr 16);
  Cstruct.BE.set_uint16 len_buf 1 (length land 0xffff);
  Cstruct.to_string len_buf

let prepend_len s =
  write_len (String.length s) ^ s

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

let create_tmp_file data =
  let name = Filename.temp_file "signhash" "bin" in
  let fd = Unix.openfile name [ Unix.O_WRONLY ; Unix.O_CREAT ] 0 in
  let l = Bytes.length data in
  let written = Unix.write fd data 0 l in
  Unix.close fd;
  if written = l then
    name
  else
    invalid_arg "couldn't write data (written <> l)"

let openssl_sign pkcs11 key_file hash =
  let hash_file = create_tmp_file (Cstruct.to_bytes hash) in
  let sig_file = Filename.temp_file "sig" "bin" in
  let cmd = match pkcs11 with
    | None ->
      Printf.sprintf "openssl dgst -sha256 -sign %s -out %s %s"
        key_file sig_file hash_file
    | Some pin ->
      Printf.sprintf "pkcs11-tool -l --pin %s -s --id %s -m SHA256-RSA-PKCS -i %s -o %s"
        pin key_file hash_file sig_file
  in
  let signature =
    if Sys.command cmd = 0 then
      read_file sig_file
    else
      invalid_arg "openssl returned non-zero exit code"
  in
  Sys.remove hash_file;
  Sys.remove sig_file;
  signature

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

let sign flags key_file changelog_file version_file image_file output_file =
  let version = read_file version_file |> String.trim in
  let version_ok =
    match String.split_on_char '.' version with
    | [ major ; minor ] ->
      (match int_of_string_opt major, int_of_string_opt minor with
       | Some _, Some _ -> true
       | _ -> false)
    | _ -> false
  in
  if not version_ok then
    invalid_arg "Version file must contain only a version number: MAJOR.MINOR";
  let update_hash hash bytes = Hash.feed hash (Cstruct.of_bytes bytes) in
  let hash = Hash.empty in
  let hash = read_file_chunked changelog_file hash true update_hash in
  let hash = Hash.feed hash (Cstruct.of_string @@ prepend_len version) in
  let filesize = (Unix.stat image_file).Unix.st_size in
  let block_size = 512 in
  let blocks = (filesize + (pred block_size)) / block_size in
  let pad_buf =
    let padding = block_size - (filesize mod block_size) in
    if padding = block_size then
      Cstruct.empty
    else
      Cstruct.create padding
  in
  let blocks_buf =
    let l = Cstruct.create 4 in
    Cstruct.BE.set_uint32 l 0 (Int32.of_int blocks);
    l
  in
  let hash = Hash.feed hash blocks_buf in
  let hash = read_file_chunked image_file hash false update_hash in
  let hash = Hash.feed hash pad_buf in
  let final_hash = Hash.get hash in
  let signature = openssl_sign flags key_file final_hash in
  let signature = prepend_len signature in
  let fd = match output_file with
   | None -> Unix.stdout
   | Some filename ->
     if Sys.file_exists filename
     then invalid_arg "Output file already exists"
     else Unix.openfile filename [Unix.O_WRONLY ; Unix.O_CREAT] 0o400
  in
  let write_chunk () bytes =
    let written = Unix.write fd bytes 0 (Bytes.length bytes) in
    assert (written = Bytes.length bytes)
  in
  write_chunk () @@ Bytes.unsafe_of_string signature;
  read_file_chunked changelog_file () true write_chunk;
  write_chunk () @@ Bytes.unsafe_of_string @@ prepend_len version;
  write_chunk () @@ Cstruct.to_bytes blocks_buf;
  read_file_chunked image_file () false write_chunk;
  write_chunk () @@ Cstruct.to_bytes pad_buf;
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

let command =
  let doc = "Sign a NetHSM software image" in
  let man = [ `S "BUGS"; `P "Submit bugs";] in
  Term.(term_result (const sign $ pkcs11_pin $ key $ changelog $ version $ image $ output)),
  Term.info "sign_update" ~version:"%%VERSION_NUM%%" ~doc ~man

let () =
  match Term.eval command with `Ok () -> exit 0 | _ -> exit 1
