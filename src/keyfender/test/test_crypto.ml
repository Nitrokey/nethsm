open OUnit

let data = Mirage_random_test.generate 32
let adata = Cstruct.of_string "my additional data"

let basic_enc_dec_ok_1_byte () =
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  let data = Cstruct.create 1 in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_random_test.generate ~key ~adata data
  in
  "decrypting an encrypted data works" @?
  match Keyfender.Crypto.decrypt ~key ~adata encrypted with
  | Ok data' -> Cstruct.equal data data'
  | _ -> false

let basic_enc_dec_ok_multiple_bytes () =
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_random_test.generate ~key ~adata data
  in
  "decrypting an encrypted data works" @?
  match Keyfender.Crypto.decrypt ~key ~adata encrypted with
  | Ok data' -> Cstruct.equal data data'
  | _ -> false

let basic_enc_dec_fail_not_authenticated () =
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_random_test.generate ~key ~adata data
  in
  let key' = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  "decrypting an encrypted domain key fails (wrong unlock key)" @?
  match Keyfender.Crypto.decrypt ~key:key' ~adata encrypted with
  | Ok _ -> false
  | Error _ -> true (* expecting the not authenticated message *)

let basic_enc_dec_fail_bad_adata () =
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  let encrypted =
    Keyfender.Crypto.encrypt Mirage_random_test.generate ~key ~adata data
  in
  let adata' = Cstruct.of_string "some other adata" in
  "decrypting an encrypted domain key fails (wrong adata)" @?
  match Keyfender.Crypto.decrypt ~key ~adata:adata' encrypted with
  | Ok _ -> false
  | Error _ -> true (* expecting the not authenticated message *)

let basic_enc_dec_fail_too_small () =
  let key = Keyfender.Crypto.GCM.of_secret (Mirage_random_test.generate 16) in
  "decrypting an encrypted domain key fails (bad encrypted)" @?
  match Keyfender.Crypto.decrypt ~key ~adata Cstruct.empty with
  | Ok _ -> false
  | Error _ -> true (* expecting the data too small message *)

let unlock_key passphrase =
  let salt = Cstruct.of_string "ABCDEF" in
  Keyfender.Crypto.key_of_passphrase ~salt passphrase

let kdf () =
  let passphrase = "einszweidreivier" in
  let unlock = unlock_key passphrase in
  "run KDF twice results in the same unlock key" @?
  Cstruct.equal unlock (unlock_key passphrase)

(* translate from ounit into boolean *)
let rec ounit_success =
  function
    | [] -> true
    | RSuccess _::t
    | RSkip _::t ->
        ounit_success t
    | RFailure _::_
    | RError _::_
    | RTodo _::_ ->
        false

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug);
  let tests = [
    "basic encryption and decryption of a single byte" >:: basic_enc_dec_ok_1_byte;
    "basic encryption and decryption of multiple bytes" >:: basic_enc_dec_ok_multiple_bytes;
    "basic encryption and decryption fail (not authenticated)" >:: basic_enc_dec_fail_not_authenticated;
    "basic encryption and decryption fail (bad adata)" >:: basic_enc_dec_fail_bad_adata;
      "basic encryption and decryption fail (data too small)" >:: basic_enc_dec_fail_too_small;
    "KDF" >:: kdf;
  ] in
  let suite = "test crypto" >::: tests in
  if not (ounit_success (run_test_tt suite)) then exit 1
