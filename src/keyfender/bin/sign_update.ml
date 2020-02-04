
module Pss_sha256 = Nocrypto.Rsa.PSS(Nocrypto.Hash.SHA256)

let prefix_len s =
  let len_buf = Cstruct.create 3 in
  let length = String.length s in
  assert (length < 1 lsl 24); (* TODO *)
  Cstruct.set_uint8 len_buf 0 (length lsr 16);
  Cstruct.BE.set_uint16 len_buf 1 (length land 0xffff);
  Cstruct.to_string len_buf ^ s

let sign_update key u =
  let signature = Pss_sha256.sign ~key (`Message (Cstruct.of_string u)) in
  prefix_len (Cstruct.to_string signature)

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

let sign key_file changelog_file version image_file output_file =
  let key =
    read_file key_file |> Cstruct.of_string |> X509.Private_key.decode_pem |>
    function
    | Ok `RSA key -> key
    | Error `Msg m -> invalid_arg m
  in
  let changes = read_file changelog_file in
  let image = read_file image_file in
  let content = prefix_len changes ^ prefix_len version ^ image in
  let signature = sign_update key content in
  let content' = signature ^ content in
  (match output_file with
   | None -> Printf.printf "%s" content'
   | Some filename ->
     if Sys.file_exists filename
     then invalid_arg "Output file already exists"
     else
       let fd = Unix.openfile filename [Unix.O_WRONLY ; Unix.O_CREAT] 0o400 in
       let length = String.length content' in
       let rec write off =
         if off = length
         then ()
         else
           let written = Unix.write fd (Bytes.unsafe_of_string content') off (length - off) in
           write (written + off)
       in
       write 0;
       Unix.close fd);
  Ok ()

open Cmdliner

let key =
  let doc = "private key filename" in
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
  let doc = "Sign a NitroHSM software image" in
  let man = [ `S "BUGS"; `P "Submit bugs";] in
  Term.(term_result (const sign $ key $ changelog $ version $ image $ output)),
  Term.info "sign_update" ~version:"%%VERSION_NUM%%" ~doc ~man

let () =
  Nocrypto_entropy_unix.initialize ();
  match Term.eval command with `Ok () -> exit 0 | _ -> exit 1
