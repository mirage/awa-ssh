(*
 * Copyright (c) 2019 Hannes Mehnert <hannes@mehnert.org>
 *
 * All rights reversed
 *)

let () = Printexc.record_backtrace true

open Rresult.R
open Awa

let read_cstruct fd =
  let len = Ssh.max_pkt_len in
  let buf = Bytes.create len in
  let n = Unix.read fd buf 0 len in
  if n = 0 then
    failwith "got EOF"
  else
    let cbuf = Cstruct.create n in
    Cstruct.blit_from_bytes buf 0 cbuf 0 n;
    Format.printf "read %d bytes\n%!" (Cstruct.len cbuf);
    cbuf

let write_cstruct fd buf =
  let len = Cstruct.len buf in
  let bytes = Bytes.create len in
  Cstruct.blit_to_bytes buf 0 bytes 0 len;
  let n = Unix.write fd bytes 0 len in
  assert (n > 0)

let key () =
  let g =
    let seed = Cstruct.of_string "180586" in
    Nocrypto.Rng.(create ~seed (module Generators.Fortuna))
  in
  let key = Nocrypto.Rsa.generate ~g 2048 in
  let public = Nocrypto.Rsa.pub_of_priv key in
(*  let pem = X509.Encoding.Pem.Public_key.to_pem_cstruct1 (`RSA public) in
    Printf.printf "public key PEM\n%s\n%!" (Cstruct.to_string pem); *)
  let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub public) in
  Printf.printf "public key ssh-rsa %s\n%!" (Cstruct.to_string (Nocrypto.Base64.encode pubkey));
  Hostkey.Rsa_priv key

let server_key =
  match Nocrypto.Base64.decode (Cstruct.of_string "AAAAB3NzaC1yc2EAAAADAQABAAABAQCf0degdGagZpd6KUyg2rFyZxbFfOQwSVerckgHmic6cg3V9TZuum66t3hNMTGNT6/+7eCctTUkogzRb0bWuwy4wByDz85XvcPa/ZdkGAgtjMEZhf1fyjoQwgT5H6AWtl/TslUWRCF78+H5QTcDLENYp7CXIZgq2vQ95qHCqBpw1fpboe9kikADmdAKPe7NUfUbu9oRyHwYK8mUSHKxcIqd4Pok6+B/gwh3YDtpV3mX5HIlUUpmpGo9VFaJn6IltETG4okkc+hf2fpbkNols9QXW2pC8x+pbe1F9TMIuJxurmLKvoWT6hWUNtwMeF58k3e8q5tuxCuFxe4k9V4cmzx3") with
  | None -> Error "couldn't decode key"
  | Some k ->
    Wire.pubkey_of_blob k >>= function
    | Hostkey.Rsa_pub pk -> Ok pk
    | _ -> Error "bad public key"

let () =
  Nocrypto_entropy_unix.initialize ();
  let fd = Unix.(socket PF_INET SOCK_STREAM 0) in
  Unix.(connect fd (ADDR_INET (inet_addr_loopback, 22)));
  match
    server_key >>= fun pub ->
    let t, out = Client.make "hannes" (key ()) pub () in
    List.iter (write_cstruct fd) out;
    let rec read_react t =
      let data = read_cstruct fd in
      let now = Mtime_clock.now () in
      Client.incoming t now data >>= fun (t, replies, events) ->
      List.iter (write_cstruct fd) replies;
      Printf.printf "%d events\n" (List.length events);
      let t, cont = List.fold_left (fun (t, cont) -> function
          | `Established id ->
            begin match Client.outgoing_request t ~id (Ssh.Exec "ls") with
              | Error e -> Printf.printf "couldn't request ls: %s\n%!" e ; t, cont
              | Ok (t', data) -> write_cstruct fd data ; t', cont
            end
          | `Disconnected -> Unix.close fd ; t, false
          | e -> Format.printf "some event %a\n%!" Client.pp_event e ; t, cont)
          (t, true) events
      in
      if cont then read_react t else Ok "disconnected"
    in
    read_react t
  with
  | Ok x -> Printf.printf "all good %s\n%!" x
  | Error msg -> Printf.printf "failed with %s\n%!" msg
