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
  ".locked-domain-key": "ojOQRFy7R7gBwVt6nk8cxrlShJ/aI9ev+I+PkcMJz7oIpMHeHK8hizolidAhW3Bbl5cHqI2FcG2tsvcJ",
  "/authentication/.version": "uq4MnkirRS2gTpYSpyv3x6eD9qO8PipLx0PkxF8=",
  "/authentication/admin": "oI33pglZ+DkxxYAhmKqixST7hFz75VT1pxkn3TPrqCddOkjuVk929Riqkx7om/MtWMRsYxGWpXylrGQD5JkPDlFxNWMOpQ98B7oyqyhCJw5q4zHZmBDYw+TrIqeTfqo9/ZAZ6WPJWZ422ee2p/v4ak74rbEYil1gAYDtfuzTzXM5si7EK5fq/rer+HEBg14jdEDfwH4E28M87ob4Y5PxuD6g8XprL4/EowX8G/Q=",
  "/authentication/backup": "rmUfXuDtxqH/XNfGC7up6kXz6N3yV5wkaEcFlBo6rlugYNKS44lPyWZhyimaFON+oDHKetTbTRu/Kcuw7zRVDdv1zlUtjwLf67u8uUpDCjUhIF0kYzbzP5YiIQ00cg7PWp6Arovjr9BE/rapAg3aCsfkBIVPSbE75wqpMX423HQxV/BZfnY7Zwvkn5G9MxGnCzSoDr2y0/O01r01mrCO",
  "/authentication/operator": "+rAQsjMVEM7qL8uDhtZbpBRopCdsBZhAJ5qzOSwTBPbQkaNlGa8v6Go/6DlHBsJ4tC0bvYIF0YpISWZ/eXOlrFNgvwKslBC0RkWDR4LfoI1TkACZOG4T6/korHNUacasLkNsTIX5NMK9KzXHRRZ44HRMABgq0iXznbrrYNscuMa1CjKviuZ5gqBnKcsNOWueb+cJOKb0AeLR6hxn1B7Ogx/jG4MyOTb1uEtlXLleqP13fpD03g==",
  "/authentication/operator2": "FGmx2ngnNsommirMtj3x8s8FNnhhhpIA9sJJTEyF3elWLFcSU3fhLCbW59t3XNxiSWq2FxAc0JUHqLXSoQxIikCKWO9FYCK1WW0cWX+CYIRabRN8ga7QBUmdIhF17kckcRhq1jQHWLUwr7XTts5ImBhk+yFzXaWMhQvUWAVFzHf6wJkqG1Nt45zam1rJenFEsHfSDAwJ6tGJOnyZHIxsZGvMdnAYZEj80bUbf5uEo9Z4WwKpqtI=",
  "/config/backup-key": "D8AwTTR++ug20OO0nOXOB/twE1KZpXZScY9LPDHWsD0=",
  "/config/backup-salt": "hDUwqayCkKEFfh+xshLNuA==",
  "/config/certificate": "AAABITCCAR0wgcSgAwIBAgIIYaPUE+WmcpcwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJa2V5ZmVuZGVyMCAXDTcwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAUMRIwEAYDVQQDDAlrZXlmZW5kZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQOYJ88NyYKBLNb4nt3unWYYbHN9ZPUHUS+dzILWaC8ghvI1MBnonC2G6qlchpJXGj0QyUXnsTIzON2mSurxDCNMAoGCCqGSM49BAMCA0gAMEUCIQCMZQI8jv/lyelu/pOmywcfFeyrPLnZk+e4Gh+kbXM2pgIgGJEi0nT76U4D1YRscg/HHYrEl5hUrcI0ClEybndMsOE=",
  "/config/private-key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNCc08xT0IvWW1CbCtUM1prNDIKY3dBV2hwOVgweUhDdDhvemkwTU40UkpGVmc9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
  "/config/time-offset": "LTg2NDAwMDAw",
  "/config/unlock-salt": "wJ1WGdcsKOwR4tFFzXafXA==",
  "/config/version": "MA==",
  "/domain-key/attended": "Yb6Em5WY2dUxOR3RWAwwSur5YHpzf1sWB9J02aYyftxsqnLrlADQH58nUEK8p3b4u3iUaqRAx+k79/sCfGKYil6OEi4UoBy378yGmotERAYXJN/oVXbSTQ==",
  "/key/.version": "AcAzKz6sTmvQvxhMBECjVRvuWdF1xW+mvm7N5Pg=",
  "/key/keyID": "MyoNZGZ9pF7N84z2tbjhs28jRz+59bHPGNn1z5inRZXfyY1qvrIBfFOiH8WuHveIEPzpCq008JdETg1+Ayh/TazhPDwDTJQeieV9iHfwDZ+fZeHMbvoAmsOjJKZ/h2zz+8d/f1UraLKWxQg/C/5bzmRmG4cPog7UE8dHPGMOHWxDlbB/8I1royFK6MsmWO/TYMXSjT8uRhHDw0LfaMwUdZ8HF0PRHbLG7SZOybq32ukr7cABQXNxgN/fv1xCkhBDV3312fZuzlwH1jUDw87+I4JvD1oTPcHkhrZoDAO1pvySmF8NjpipzAlDcWQaUS4gv18UynBv0Aw2V32GCx/jha7xyhG9bQPmG/xw85oEOz7i5b41tnHyTYH+eagH1ZClL0a2I1FSx5IzIazpaBLRPbyL82adFt1oOQReUxQP0lKhdDSJk896+bVJfdqb7hY7Kfoc55sHra96GzLL9g+1zUcX+91xokSd+rirhfaQZy0VXBHJbNgkhTo9r9Jl+42L7aizO6wUf8bNVEVbSB/sFQmQODt870AA5YfrG1Fs/5ejbw8nbYUFg1AmOr+c6Sy6XWpUko7Tdr1n20HHNaFMMMzco7B6sglLaUKW4VuKX6V1s98P+iodsHQIaXNzBnwD+sDtQJqGELZRUblyCfjE7dYZiG4hyKDO3H7u4SEQ7RynI/elJ952Jx08Rr6z0As6JgCjQesQ/ZEx0eLil7vr36StxMM5jKjff0POOpWDBZU+NSeKz2cl8Xs7d353XEWYGhEx0fNMV+ge5LMJywTqxuVGBFYy9Y3Q38qcjq5SRLQ1Dd6BnfH3EiLx0H786usE5BZ3CN7+vaLro4th8qXl4cCaYMsnkGPsxaBgmDwTptqYWX2/F/pUXfpaaZUqF1gl0J6JZKi5FcLcIJ6YYPPChdyHI5krLszcZx31Ow4qnyfvtg8Cp6felsnuPeXTkIJ/9CjIjYDOhZdLMnJlDNBZFbbl8He1flAtHg+wsqtGnOZl0X2VGyBcqhjLMe1/Ge66IHTRzISUh3NHucdv7Kme0stsm//d5HifvwtiwQIEyKy6WnE7GF/ogpo2SQaGoLkQieIWDkqSXQe0ss1Zj3pNTkFsws57M5YOJNLucJkupo+SNAYGzsoKXbPkysr+t0rQaS/43IIZBPKzpFGDt3PVbx79MvoEqN1+QldIH82RFN+PH/ZPcmWcX+zrNuHH3hGI1joTFZLZQeGsIjq9zUJn2875oHXu254Jn02Z6ajUXihUBeo/kuYErUs8Q2ofZ36D9EjrX24dW82Ddtd1wwZJb6iDxUWNMIigXib3Wgdk43n+02j/k5/FQV2BBVh4lLog04ul/194D7gU34AArHc3cktUntgj5ZQFkJeV+v/+f8Uj5eCxAylpaLqLuI3imwon5nW9f8Tb"
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
