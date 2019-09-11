open OUnit

let domain_key = Mirage_random_test.generate 32

let basic_enc_dec_ok () =
  let unlock_key = Mirage_random_test.generate 16 in
  let encrypted =
    Keyfender.Crypto.encrypt_domain_key
      Mirage_random_test.generate ~unlock_key domain_key
  in
  "decrypting an encrypted domain key works" @?
  match Keyfender.Crypto.decrypt_domain_key ~unlock_key encrypted with
  | Ok data -> Cstruct.equal data domain_key
  | _ -> false

let basic_enc_dec_fail_not_authenticated () =
  let unlock_key = Mirage_random_test.generate 16 in
  let encrypted =
    Keyfender.Crypto.encrypt_domain_key
      Mirage_random_test.generate ~unlock_key domain_key
  in
  "decrypting an encrypted domain key fails (wrong unlock key)" @?
  match Keyfender.Crypto.decrypt_domain_key ~unlock_key:(Mirage_random_test.generate 16) encrypted with
  | Ok _ -> false
  | Error _ -> true (* expecting the not authenticated message *)

let basic_enc_dec_fail_too_small () =
  "decrypting an encrypted domain key fails (bad encrypted)" @?
  match Keyfender.Crypto.decrypt_domain_key ~unlock_key:(Mirage_random_test.generate 16) Cstruct.empty with
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
  let tests = [
    "basic encryption and decryption" >:: basic_enc_dec_ok;
    "basic encryption and decryption fail (not authenticated)" >:: basic_enc_dec_fail_not_authenticated;
    "basic encryption and decryption fail (data too small)" >:: basic_enc_dec_fail_too_small;
    "KDF" >:: kdf;
  ] in
  let suite = "test crypto" >::: tests in
  if not (ounit_success (run_test_tt suite)) then exit 1
