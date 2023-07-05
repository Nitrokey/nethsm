(* Copyright 2023 - 2023, Nitrokey GmbH
   SPDX-License-Identifier: EUPL-1.2
*)

let output = {|{
  "/key/myKey1": "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",
  "/key/.version": "GUGna8ZDg0xE6o1IzeYR0iL2kkCmiEdLfmx2zVM=",
  "/domain-key/0": "bn5Z6ImokJrlk2HWz5SP8SRRbzZwDN6/axZSOYUicaJ2FaVn7zc61GPJX8BpZAMS8WLHKxfdvoSdORhmMFlF6sD2MH0Kk1rlvr7TVgrCjls8VEnPuZ6nhiFU4tg=",
  "/config/version": "MA==",
  "/config/unlock-salt": "CWp2KEolfKtYfpTnfDaBTQ==",
  "/config/time-offset": "LTI=",
  "/config/private-key": "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQzlMazZVUTQ5ZTBBRmsKdEpBRWtReU5FYW9XM0pxN25SUlpyWkNuSWx5V2orTmRqK0pVVFhpaUN2Z0xhZU5CbEc4dk95eTRITXVIQnZ5WQpvSDI3V1NoN2ZHMXAvL0h5QktEOGFGUTJHWmZyZ1pSYlJDUUI2VkpuNC9ZMjRXM3k0NE52dFp1RHlnUVkzODdCCmwxU2Z1UUxqLzFkTVhYOUlSNStNMG5yWkY4bnc1dUxDa1JuM2xCQ09DaTFSbHlMcEtXeEZvS1NUVzVCaWxhMEgKWitEMENNOE4vUW53ZFRnQXhUSDVHdUFwamJsd21lZVdwUzdUdndXMUtyNXZ4UXNQQThydVM2cktyTDlYcDJxKwpHQXBkNEYxc0tPRy82aWJaU2JXYk01Z3pUNVFmVFYvUlFrRlVSd1dZU2FLVXlaM3ppTko3L1NrcFZ1OUh5WmVCCkhtQUoxbEcxQWdNQkFBRUNnZ0VBYm5Ud0tuODc0YmIvYVVaSDVIS3dhbG1LL3lnMUxCL3Q5dUp4V0RTbTdMMzgKbWU5ZHphMGlKekxTV3crclFlb2g5T2pQRm55eGxSaE9PZXRUSGlWVGpxNDYwQzVCblBaNDdJY1p6RENyVkRWbgpZdFpwVTdoZ2hncERBdzRpZlRPNzFXaXE4WXJ0VTN5eG9yVHlFd1FhSFBkRWlIRDYxVUFFZDF1Wm9OSFQ5ZFJJClM1VU5sRUk4bFYvdWFwMjJJRkErR2ZEVTlYUGx6OG94YWN6bzRiODg5OGVEOWx2d2MydHhodFF6NWM5dFUxV3gKVW8yR1M3ekNhMk5ZYWlCT0w2OG1xdHZwd0d5TzU4eURONFlLQlMvNU9TSUxleDR1T2tmeXFNQ3FIcnYySUlLTApuVXhCZEdZUmRrWnhBbW9sQTFmc1JQdVRtRm96TzQxbDBGZkUyVTlxNFFLQmdRRGNJQW1PN0s2WEorOXlFcjZNCm4yWUx5NCtjYUt4U1FPWnZHMHRiTWc2Ym04eXBiUzFtZVluRFZnTnZ0U1F1TWIvYUF4OGNrVWtkUm42RDVXaTIKanZnNzlmeFZrSzdIbVBweDB2a3NMNzUxVTF0L2xDbVNRUlJYYU1qSHZFK1VFSWw0Y2xQdjBnNzFvUjZTNE5DLwphdVFOS3lpZ0F3VlpKcFBhaDNCeDJRcWQ3UUtCZ1FEY0F6b2k5OHBhYnJ6dUFjaXFpRkJnWUEvdHZzcjR4UkovCkF0elNGcDdzQllEdmJlN00xRTk5WGZhekIxakFLcDdhbHJXU21qY2p1Zmp1MkRQdXdZR2htR3BpU2t0QjNPNisKVTFhdU5BOWIwckdyS3B4S1lrak5xRTgrc2taR1hrNmNVSTM1ZzlQc3NVb3p4d2dObWtlR2lTRVJUeEEwdmdsOApvWDMrZERSSjZRS0JnQjdyeVN2d2gxM29XRFJYK2JoYk04UjRaY1g4MWlmL3dkN2RvS3BBejloLy9ESFlpa1lZCjBJZEY3OW1qUWwvUzBUWll0ZWdYYUlQYVFTOVo3R21vajZvc2xiT1hUVlh3WVUzWDZ2U1FDRnNHeUpXVlJIbXMKOXFTSXJadVJFa1NrUmd0TFZBc2VJTWZVU0MwdHMyVVFLTlRJdVQ0dzduRmxmK04wbnhEL0FnVEpBb0dBY0ZXZAplM2sxY3BNVUdCb0ZFVDFrZkxEUHNUNDNlR2wzRmk2cC9RTGJ4ZnJSYUc2aS9TWnlKN3F3V1p5b3JnV1U4bHI4Ci9vdUxGOHkrMDRURWoyVnlBTVpIbTBQL3hQTS9XeUpHSWRBbS8yVkduZlMxdEMwV3F4c0N5eXBQUTJLbmxKeDAKd1MrVUowZ21jT1Z3c1RGU3o5aDRiOVFFbkVsam9xVDZKYy9EV3ZFQ2dZQW9BNmgreDI5ZW9wbmZ5ak41b1NTYQpINHB1SzVCS2hoaGNWM0xqaG1tZnEvaVlNYThtc3RNdzNyN2p4aVlLdDgzUmZXbWF4VENxemJ6bWZhbXFWSFJtCkJjSmdqRDlkektNUGhXbUdGUmgzbnlIYjM5cU9oVi9YdzZSM1hXbUtnRTlhV0pnMUdEUUlWbWVqVGZjSGZ4aEsKMGxjdmNNWTFsQlJ2UHBoMHdTME1IUT09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
  "/config/certificate": "AAACrjCCAqowggGSoAMCAQICCA0ZpAFn9Zp9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWtleWZlbmRlcjAgFw03MDAxMDEwMDAwMDBaGA85OTk5MTIzMTIzNTk1OVowFDESMBAGA1UEAwwJa2V5ZmVuZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvS5OlEOPXtABZLSQBJEMjRGqFtyau50UWa2QpyJclo/jXY/iVE14ogr4C2njQZRvLzssuBzLhwb8mKB9u1koe3xtaf/x8gSg/GhUNhmX64GUW0QkAelSZ+P2NuFt8uODb7Wbg8oEGN/OwZdUn7kC4/9XTF1/SEefjNJ62RfJ8ObiwpEZ95QQjgotUZci6SlsRaCkk1uQYpWtB2fg9AjPDf0J8HU4AMUx+RrgKY25cJnnlqUu078FtSq+b8ULDwPK7kuqyqy/V6dqvhgKXeBdbCjhv+om2Um1mzOYM0+UH01f0UJBVEcFmEmilMmd84jSe/0pKVbvR8mXgR5gCdZRtQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAR4m88BpqCX6UNQnCwi82evTZY1twqg585I/2UpzXzQKwnrWhG0SbjaxqyPwRkXn4dgBq6wN8FPYYx1vdgx4nEbGZrXgCbFHpEGROo4KyGQxAp3G/Z2J1uUFDj6QFbDLQAfFvJOaGuwaux/QppY6vDD4AhmByZXGGO1TlrYJ9J4AzIVvikekm4I6cFZLkz4NlvL1Z9DD43bPxKFTagcdXUZDtjW5TXkDQGP9uUpbtp3u60jkX8N0TVVnnwWqCReaCnFXzEVvwnSe8mBSDHdRt3/gNK1e1/R9Yj8QI0cCtv5T1FZIl/EYdwEA5HRp2wYjA1mNXNBCS2nW8H+SrJTH/6",
  "/config/backup-salt": "AX/f6PfPApY07lD2Kgr+sA==",
  "/config/backup-key": "i9ilIN0JFezdUKB9uZgT3JAlLTrYzEPYCNTPKZqVcDw=",
  "/authentication/operator": "kqA2f5PqYlQoA8hNiYchgxBBjKgsdiX7ch4j/dCewz5EFd8vfVWvrXPh25PeFffZv6SvqSDJmQTx+QHjoza1v4ATi9bYO+5eTcUbf1JfTLasyQJnjAFHpfm+vXKVi8YAjrSl5n2YqFSOsxE47Gt9YKFqvpssqHHV6DhuQ2uow/hkk1J5wUys+vPr8VUyvvcUflWD6BBRqdJOVaY4ncY+LKxg/KpYY7y1MC9lRNo=",
  "/authentication/metrics": "1slwJGlLGvV4Zyn+3paPV/qLhHxW/FCGrGTsuLk7z1qpSXMu8/nKd/mY/4DGk8CFcRWEy1x48+4ZwJXYzxemxvYDJBa3LT8vGmgrKuI0EOw2YloKh1Xb/Yuzsgw6iDixDilG4bFpsDDeITJwh3HZv+MLtzaCQoeD6J+RSGIvEftBe2htVnXsInVyYuCX2ndK4JW5QVk/BXp9pyiE86r/VlE=",
  "/authentication/backup": "yoJh7fwkJL/S3JIDW8XFk0AKDurPRQiBE4ePvJCJhUj0w2iykXsKP6+S8tdM9ldManFlKw6AwmnTb6yyPRdyqlMxq8H0EG7FSKd5BCny7+4GqP6fQP/FaiN16eELHKJ4gKQgeGs+grVsGk8jl7jKUMFOdPRRRnHrsC3vIeSwc76WhF0jirBjNeG+utzg+fiyRZL1MKq09c8ClwE0uTUdWN67NPtkjnk=",
  "/authentication/admin": "KAM7QPHDT+zrXihTBF8d3dzOG+cDgT15JlZXrhJQWEZFnaVTpyB5uWSXla6IDOxr5xopfzJyMBlXnyixXnFnEItp3s2EzLAiYmrfPB2NMqQzwHk1KfnkaDzY97TL5lFePoMd9ulzpGip+uGJGY5Zfd2Bw1h8cxHb6H18vle6BDpJ6IEGt7xwvYfTBbtOuiWzoRW6n8+v8Sy/yQGb0JzTTF064XyD1QGicTo=",
  "/authentication/.version": "BVyX5zHSHxsLsBQ/ATF+IB93/rPOLb+g1IdK+bs=",
  "/.gitignore": ""
}|}

let readfile filename =
  let fd = Unix.openfile filename [Unix.O_RDONLY] 0 in
  let filesize = (Unix.stat filename).Unix.st_size in
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

let () =
  let returncode = Sys.command "../bin/export_backup.exe BackupPassphrase my_backup.bin --output=my_backup.json" in
  assert (returncode = 0);
  let body = readfile "my_backup.json" in
  assert (String.equal output body)
