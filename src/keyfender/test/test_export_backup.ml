(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

open Test_utils
open Test_dispatch_helpers

let () =
  Printexc.record_backtrace true;
  Fmt_tty.setup_std_outputs ();
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level (Some Debug)

let backup_v0 = {|{
  "domain-key": "ojOQRFy7R7gBwVt6nk8cxrlShJ/aI9ev+I+PkcMJz7oIpMHeHK8hizolidAhW3Bbl5cHqI2FcG2tsvcJ",
  "/authentication/.version": "uq4MnkirRS2gTpYSpyv3x6eD9qO8PipLx0PkxF8=",
  "/authentication/admin": "oI33pglZ+DkxxYAhmKqixST7hFz75VT1pxkn3TPrqCddOkjuVk929Riqkx7om/MtWMRsYxGWpXylrGQD5JkPDlFxNWMOpQ98B7oyqyhCJw5q4zHZmBDYw+TrIqeTfqo9/ZAZ6WPJWZ422ee2p/v4ak74rbEYil1gAYDtfuzTzXM5si7EK5fq/rer+HEBg14jdEDfwH4E28M87ob4Y5PxuD6g8XprL4/EowX8G/Q=",
  "/authentication/backup": "rmUfXuDtxqH/XNfGC7up6kXz6N3yV5wkaEcFlBo6rlugYNKS44lPyWZhyimaFON+oDHKetTbTRu/Kcuw7zRVDdv1zlUtjwLf67u8uUpDCjUhIF0kYzbzP5YiIQ00cg7PWp6Arovjr9BE/rapAg3aCsfkBIVPSbE75wqpMX423HQxV/BZfnY7Zwvkn5G9MxGnCzSoDr2y0/O01r01mrCO",
  "/authentication/operator": "+rAQsjMVEM7qL8uDhtZbpBRopCdsBZhAJ5qzOSwTBPbQkaNlGa8v6Go/6DlHBsJ4tC0bvYIF0YpISWZ/eXOlrFNgvwKslBC0RkWDR4LfoI1TkACZOG4T6/korHNUacasLkNsTIX5NMK9KzXHRRZ44HRMABgq0iXznbrrYNscuMa1CjKviuZ5gqBnKcsNOWueb+cJOKb0AeLR6hxn1B7Ogx/jG4MyOTb1uEtlXLleqP13fpD03g==",
  "/authentication/operator2": "FGmx2ngnNsommirMtj3x8s8FNnhhhpIA9sJJTEyF3elWLFcSU3fhLCbW59t3XNxiSWq2FxAc0JUHqLXSoQxIikCKWO9FYCK1WW0cWX+CYIRabRN8ga7QBUmdIhF17kckcRhq1jQHWLUwr7XTts5ImBhk+yFzXaWMhQvUWAVFzHf6wJkqG1Nt45zam1rJenFEsHfSDAwJ6tGJOnyZHIxsZGvMdnAYZEj80bUbf5uEo9Z4WwKpqtI=",
  "/config/backup-key": "jCNuY5KlowQ3YLX+JwxExdvRyJCVO7eLc0YtMUnKk3M=",
  "/config/backup-salt": "M0M78euFov0g63QlT19JaA==",
  "/config/certificate": "AAABITCCAR0wgcSgAwIBAgIIE97rgxebxQcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJa2V5ZmVuZGVyMCAXDTcwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAUMRIwEAYDVQQDDAlrZXlmZW5kZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR6K6fFwEP1maCbAxSjqr1BwS0mfpWzR97h/Ac3nmxyVfiZAlqoskDvZ+tO9GRUlq8OppxGueHYvn0PG3HlPuTiMAoGCCqGSM49BAMCA0gAMEUCIC1+X8EKjzYSAHfGR3/stFHy9jdGVunBohoRv9SnCBLBAiEAmbl0AlTydqYR1y372V79WMoh858ZGnOF4rLQ5RtqmRo=",
  "/config/private-key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNDckNtaTJiZWg4VjAxZXUzWkIKTFl5dTZmWnBPUmIwQnJhVi80NEZGWUZNRVE9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
  "/config/time-offset": "LTg2NDAwMDAw",
  "/config/unlock-salt": "wJ1WGdcsKOwR4tFFzXafXA==",
  "/config/version": "MA==",
  "/domain-key/0": "Yb6Em5WY2dUxOR3RWAwwSur5YHpzf1sWB9J02aYyftxsqnLrlADQH58nUEK8p3b4u3iUaqRAx+k79/sCfGKYil6OEi4UoBy33g1yLJb0UBPPBq0PVc8h8A==",
  "/key/.version": "AcAzKz6sTmvQvxhMBECjVRvuWdF1xW+mvm7N5Pg=",
  "/key/keyID": "0en/jhBIXI/lErGWc6JAIQn6JNOzcj+PG/Y1NKzudkTH6JgybuWvjEJ5/i+bFidzT1Nk91hVd5zx2/St2LnCAHu9776hffTT59GjIermCNwq9IFrnjx8eeaaqKsx7ueTmayltYY8OYgXrbK3pMU/XsKZtEWUavbwWgXMbTQyyBqLCxqJBH3SzGl5o1Y/FM92hWUAIO5vQClYpFZ7xBXR8Z1fNak05dhMHYVcvdGkb1yqnhZ2PGdotF6OjbVzjEW7Eb+eFLMyWNNXwRNNfdCWUtfcff/ecvzl9RY3b/tJci85LBB0EMKS57c+m/uMDqQAZzaRvkX8sjxgC+meaOhT7t/sv7yi1XipySYlPL51rVniR3rd8yjc99TIWfIBA3fJw0igjaKaqLZRPt5maCpxjMfzds1NLEEXX85x5i9HQ5m+zml7AylYcp7ORuDaxdVoOMnNc0cDOsIjcUqD0ji/Df45AVnWCzzK6ORsmACi9uXKsVd4aqp/va+4mPYhwhkwSTGbfOtawAwD5+hITzuYfkA6norrtPzcgbIOT7qLcKq7hCCo85fdrTmINKJx9kVWg+F+2Avv00XFTw+AcoeEYx6HmjRaTfFoqu2KRKkP9swBJBKt2jHUrPhuwFWhUYabMtcA7T5QnBYWCa7rQ//BmV7LsDn7a3qNWKVGSc7gEuXy4O5v05TeaAGt3EhdW0gxqhTfCiKIT4xke6eTPtoJkmRGdjWz8VExYyY/bpt7sUYs9dsEfu0IUnHRcRRiFXKrVTgCIj9SQjGXrRwRDx3AFxUVgOh4YSXvWV74JVoVEo5WDRTVlCMjGr0qRBC7XsMSSG7y92WmNVpnTRjJ6r/bRzZKyVlRyFjZ1BlQVjHOjHC9d7xPmAYxQYCG7VB5ZvOHO50ACyg/4wYdG0vyFuldxx+jeyUJlWa9wULLbLl9dp7JN5VLNTIfspCARs/Klki0vudxYMEhhR1QtSoQCnpncHMEm71SsHefwOs/3yayTsc+H3aWiYME3fDU8aOgkj2DjtWvLjsXQdwbDUGXnUb/CQFtMph6EDq6oaPqW52siyCaafV9snIhMTON6ONl0gldmui79Cj0ntRcdeqRBiegQuiGOMTNJW0hGQjFWElWMPvUVdiTk+4eRqd25hMxqI7hY87bonHbt6+AeGzatQZfILfEdZwiClwN31UcHkIiwp03ZlEIOmBCTaAXk/WH/FVg3zqD6hwveS900WztfFaGoiQrsHIaK+oBYty14FGB0tlmFKKLO/s3sG9320xOrBCSjttE4S9a5BPztUYW/7gzp+LQdwpQ0nIkIL037ScB7X7now8FZ4gdYqN6VTm4lT9a4UnSKl9++uE3fPPK07Jt0e3OzxtOkRhozYbmnLoJdKGLdU4yossnOKI1pet8LnPCJBGSeNc5"
}|}

let export_backup_current =
  Alcotest.test_case
    "current backup format can be handled"
    `Quick
  @@ fun () ->
  let backup_passphrase = "BackupPassphrase" in
  let passphrase = Printf.sprintf "{ \"passphrase\" : %S }" backup_passphrase in
  let hsm_state = hsm_with_key () in
  let* hsm_state =
    admin_put_request ~hsm_state ~body:(`String passphrase) "/config/backup-passphrase"
    |> Expect.no_content
  in
  let headers = auth_header "backup" "test3Passphrase" in
  let* _hsm_state, s =
    request ~meth:`POST ~hsm_state ~headers "/system/backup"
    |> Expect.stream
  in
  let data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
  let f = open_out_bin "my_backup_gen.bin" in
  output_string f data;
  close_out f;
  let returncode = Sys.command "../bin/export_backup.exe BackupPassphrase my_backup_gen.bin --output=my_backup_gen.json" in
  Alcotest.(check int) "returncode" 0 returncode

let export_backup_v0 =
  Alcotest.test_case
    "v0 backup format can be handled"
    `Quick
  @@ fun () ->
  let returncode = Sys.command "../bin/export_backup.exe BackupPassphrase my_backup.bin --output=my_backup.json" in
  Alcotest.(check int) "returncode" 0 returncode;
  let f = open_in_bin "my_backup.json" in
  let body =  really_input_string f (in_channel_length f) in
  close_in f;
  Alcotest.(check string) "json" backup_v0 body

let () =
  let open Alcotest in
  run "export_backup.exe" [
      "export_backup_current", [ export_backup_current ];
      "export_backup_v0", [ export_backup_v0 ];
    ]
