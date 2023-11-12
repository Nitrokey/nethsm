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

let backup_v0 =
  {|{
  ".locked-domain-key": "ojOQRFy7R7gBwVt6NgiTu0oO7ra+1XSD+spC+ot9ftg3oGii5066mkX3yhqnChaAYlXB/+IViMExKgYX",
  "/authentication/.version": "uq4MnkirRS2gTpYSpyv3x6eD9qO8PipLx0PkxF8=",
  "/authentication/admin": "oI33pglZ+DkxxYAhmKqixST7hFz75VT1pxkn3TPrqCddOkjuVk929Riqkx7om/MtWMRsYxGWpXylrGQD5JkPDlFxNWMOpQ98B7oyqyhCJw5q4zHZmBDYw+TrIqeTfqo9/ZAZ6WPJWZ422ee2p/v4ak74rbEYil1gAYDtfuzTzXM5si7EK5fq/rer+HEBg14jdEDfwH4E28M87ob4Y5PxuD6g8XprL4/EowX8G/Q=",
  "/authentication/backup": "rmUfXuDtxqH/XNfGC7up6kXz6N3yV5wkaEcFlBo6rlugYNKS44lPyWZhyimaFON+oDHKetTbTRu/Kcuw7zRVDdv1zlUtjwLf67u8uUpDCjUhIF0kYzbzP5YiIQ00cg7PWp6Arovjr9BE/rapAg3aCsfkBIVPSbE75wqpMX423HQxV/BZfnY7Zwvkn5G9MxGnCzSoDr2y0/O01r01mrCO",
  "/authentication/operator": "+rAQsjMVEM7qL8uDhtZbpBRopCdsBZhAJ5qzOSwTBPbQkaNlGa8v6Go/6DlHBsJ4tC0bvYIF0YpISWZ/eXOlrFNgvwKslBC0RkWDR4LfoI1TkACZOG4T6/korHNUacasLkNsTIX5NMK9KzXHRRZ44HRMABgq0iXznbrrYNscuMa1CjKviuZ5gqBnKcsNOWueb+cJOKb0AeLR6hxn1B7Ogx/jG4MyOTb1uEtlXLleqP13fpD03g==",
  "/authentication/operator2": "FGmx2ngnNsommirMtj3x8s8FNnhhhpIA9sJJTEyF3elWLFcSU3fhLCbW59t3XNxiSWq2FxAc0JUHqLXSoQxIikCKWO9FYCK1WW0cWX+CYIRabRN8ga7QBUmdIhF17kckcRhq1jQHWLUwr7XTts5ImBhk+yFzXaWMhQvUWAVFzHf6wJkqG1Nt45zam1rJenFEsHfSDAwJ6tGJOnyZHIxsZGvMdnAYZEj80bUbf5uEo9Z4WwKpqtI=",
  "/config/backup-key": "TysqPaKQ7F6ijdsksQ78FIGTwMJD7DBPZlrghZJxF50=",
  "/config/backup-salt": "3kQ0XzDl/BNogJRzaBCgxA==",
  "/config/certificate": "AAABIjCCAR4wgcSgAwIBAgIIFIZpWv+dFOMwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJa2V5ZmVuZGVyMCAXDTcwMDEwMTAwMDAwMFoYDzk5OTkxMjMxMjM1OTU5WjAUMRIwEAYDVQQDDAlrZXlmZW5kZXIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASNgAQj8BTFhxS2dShjeRzU+MGqEUwgw09nfprllPoPBexADmTnVzj43cDrlEJoSJ2yVca+ah9Ztd9yARh9+G1KMAoGCCqGSM49BAMCA0kAMEYCIQCPu1ZbEN56nxnwKn/EoragYKvtRg+D0jtlWlSTjSrf4QIhAJfItxp4II2bSaBgA0dn9U0FNwo7GRyJiL9ngZkeDXs7",
  "/config/private-key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1FRUNBUUF3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRUp6QWxBZ0VCQkNEQmx2MzR4bHJrWFhObm9YbW0KU2lIb0pyMS84OFRDbHlrbG8xVzh2TkxRMGc9PQotLS0tLUVORCBQUklWQVRFIEtFWS0tLS0tCg==",
  "/config/time-offset": "LTg2NDAwMDAw",
  "/config/unlock-salt": "wJ1WGdcsKOwR4tFFzXafXA==",
  "/config/version": "MA==",
  "/domain-key/attended": "Yb6Em5WY2dUxOR3RWAwwSur5YHpzf1sWr5X7pFVuFPUIXNHHlkUddNdT4SCDo9+EQJkPe9uShCO9pp3ZiaBe3TEe6oKIOO2p5jb8TwNgi7veMF2vxt1sNw==",
  "/key/.version": "AcAzKz6sTmvQvxhMBECjVRvuWdF1xW+mvm7N5Pg=",
  "/key/keyID": "6m4MxKtSk6i9JBnF0/VpchV7BPANrlQulyjIwOZyDewxDQokQ8U5WLVqrRQSuyYx2YvZGzQtAXLlBN6uSild9pgO8Vg6zg33q2zoI6k8BmNqX1BtV9hGRimsS4fOSnkEhuhq7yyF4djy0NZoi2tPVCbHcI2dJEVLuoAV48Ob/TeD7RE3zsEtjC0HRiuJ88LlGjnnr0828JCIFVeN0BlLQo5cq1heHioj4ju1nwqS0xFUgc3JDWgCeVK19K2zxpiepzIvb9YXA5dHqNBJ3fgjEJYBYmkqZEpxVxoExdMbgtNykLcGvYt8njuNbVPU8pq09MC/n18xd6v9KBYsH+c61Sc9SPs9tsCUpnY7jJoTO2agpXWaXfesX9xRtyl6PKImIB8/BL2HA1xinzIuSIftIkf0fLoTdFg8lcPiumJnH2MwvoSr9ulnKibxVWQ733Il+NCyedKk8ozgI/NPkjH/YrAmVWQdRqpMMrkFc+1IUyta9aTSZJssyL+GoGt6pF/xikhED/QNKhwg5B3gUm6XRw4CXQY7qxnfvymlwpMfOqt3qeWuVxoYJPJygTCNY1gNcm0/mtdVesuLPkk+766UC2bxRKWGALHnBSY80p/VMEADLkmJ9kwXWy9E5qFcxVOz+j4Njm9NOZ66+72NstSJxurxmKMbhVtXBgN3XlzcfqzFmoO1hrDvSuiR7VYJTEUpFYkKHE+RY5opNsSk0Rxt2m7Pg8SOMgrt6Amj6sOxdXvVKGCHkHvE0NPR/64Fq5q3hbRr3hMB8fUfze1FNEQyYMQJCB7dk/twhmBR+D9B/iI0H1+UJty/HJtTypywfgOX0lLX2cMqs3f8QE8J6uYG4h0A6kcHkOSDmCDq/PmVSfUA1fGrqEzOPNVOCLfuxqDPFTfvm/6LVuv9VrH6sVTYkzcBQzRKGhhtXFa0eKB8m1ElNhXvKy+8cRRdwVEnqlCCBunB1ubBJC3PVa8BVzK6W7bldMwQi1WKMSxolqO4jpcbUrmYrH20uyguIPlHVUPPSAhtJs/ECFEvHtPxSDmQXED20uwSVweRnyj5oqx3NuTG6U+JGDhf+XAg1EoNmW0+RjP/ilH26qc+bKkGMXjCuX7gyu/cYSRD+ML+d85d4gmbO5g00tLRBQWECsuC1keKny1kylNkfGp0KogPjb50xawJzfHDmgcFlYebf3OcySdnGhnkH0cPXJsDANyb6xfZwqOM2HgF2TOUAMmI2WlHrqBbdJYI3h2uKxqQA1GN5JHb0RnBZPey/1OpkRl5WrZ5seNebPv9EoCvS9gZ78lXT2O2PnKBXkgMh/oz+Kbn699Pf4VVV85frGuc/qoYcMqrypf0P+0r3ptZks/rBZmQvtmVs1JPGbn4O30XMMTxmsP2r+iIY3VuIzTSrKKhbqzUyutaO0Jd"
}|}

let export_backup_current =
  Alcotest.test_case "current backup format can be handled" `Quick @@ fun () ->
  let backup_passphrase = "BackupPassphrase" in
  let passphrase =
    Printf.sprintf "{ \"newPassphrase\" : %S, \"currentPassphrase\":\"\" }"
      backup_passphrase
  in
  let hsm_state = hsm_with_key () in
  let* hsm_state =
    admin_put_request ~hsm_state ~body:(`String passphrase)
      "/config/backup-passphrase"
    |> Expect.no_content
  in
  let headers = auth_header "backup" "test3Passphrase" in
  let* _hsm_state, s =
    request ~meth:`POST ~hsm_state ~headers "/system/backup" |> Expect.stream
  in
  let data = String.concat "" (Lwt_main.run (Lwt_stream.to_list s)) in
  let f = open_out_bin "my_backup_gen.bin" in
  output_string f data;
  close_out f;
  let returncode =
    Sys.command
      "../bin/export_backup.exe BackupPassphrase my_backup_gen.bin \
       --output=my_backup_gen.json"
  in
  Alcotest.(check int) "returncode" 0 returncode

let export_backup_v0 =
  Alcotest.test_case "v0 backup format can be handled" `Quick @@ fun () ->
  let returncode =
    Sys.command
      "../bin/export_backup.exe BackupPassphrase my_backup.bin \
       --output=my_backup.json"
  in
  Alcotest.(check int) "returncode" 0 returncode;
  let f = open_in_bin "my_backup.json" in
  let body = really_input_string f (in_channel_length f) in
  close_in f;
  Alcotest.(check string) "json" backup_v0 body

let () =
  let open Alcotest in
  run "export_backup.exe"
    [
      ("export_backup_current", [ export_backup_current ]);
      ("export_backup_v0", [ export_backup_v0 ]);
    ]
