(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let () = Mirage_crypto_rng_unix.use_default ()
let data = Mirage_crypto_rng.generate 32
let adata = "my additional data"

let ( @? ) name fn =
  Alcotest.test_case name `Quick (fun () ->
      Alcotest.(check bool) "OK" true (fn ()))

let basic_enc_dec_ok_1_byte =
  "decrypting an encrypted data works" @? fun () ->
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 32) in
  let data = "X" in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data
  in
  match Keyfender.Crypto.decrypt ~key ~adata encrypted with
  | Ok data' -> String.equal data data'
  | _ -> false

let basic_enc_dec_ok_multiple_bytes =
  "decrypting an encrypted data works" @? fun () ->
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 16) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data
  in
  match Keyfender.Crypto.decrypt ~key ~adata encrypted with
  | Ok data' -> String.equal data data'
  | _ -> false

let basic_enc_dec_fail_not_authenticated =
  "decrypting an encrypted domain key fails (wrong unlock key)" @? fun () ->
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 32) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data
  in
  let key' = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 32) in
  match Keyfender.Crypto.decrypt ~key:key' ~adata encrypted with
  | Ok _ -> false
  | Error _ -> true
(* expecting the not authenticated message *)

let basic_enc_dec_fail_bad_adata =
  "decrypting an encrypted domain key fails (wrong adata)" @? fun () ->
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 32) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_crypto_rng.generate ~key ~adata data
  in
  let adata' = "some other adata" in
  match Keyfender.Crypto.decrypt ~key ~adata:adata' encrypted with
  | Ok _ -> false
  | Error _ -> true
(* expecting the not authenticated message *)

let basic_enc_dec_fail_too_small =
  "decrypting an encrypted domain key fails (bad encrypted)" @? fun () ->
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_crypto_rng.generate 32) in
  match Keyfender.Crypto.decrypt ~key ~adata String.empty with
  | Ok _ -> false
  | Error _ -> true
(* expecting the data too small message *)

let unlock_key passphrase =
  let salt = "ABCDEF" in
  Keyfender.Crypto.key_of_passphrase ~salt passphrase

let kdf =
  "run KDF twice results in the same unlock key" @? fun () ->
  let passphrase = "einszweidreivier" in
  let unlock = unlock_key passphrase in
  String.equal unlock (unlock_key passphrase)

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  let open Alcotest in
  let tests =
    [
      ( "basic encryption and decryption of a single byte",
        [ basic_enc_dec_ok_1_byte ] );
      ( "basic encryption and decryption of multiple bytes",
        [ basic_enc_dec_ok_multiple_bytes ] );
      ( "basic encryption and decryption fail (not authenticated)",
        [ basic_enc_dec_fail_not_authenticated ] );
      ( "basic encryption and decryption fail (bad adata)",
        [ basic_enc_dec_fail_bad_adata ] );
      ( "basic encryption and decryption fail (data too small)",
        [ basic_enc_dec_fail_too_small ] );
      ("KDF", [ kdf ]);
    ]
  in
  run ~argv:Sys.argv "crypto" tests
