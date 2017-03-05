(*
 * Copyright (c) 2016 Christiano F. Haesbaert <haesbaert@haesbaert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

let () = Printexc.record_backtrace true

open Rresult.R
open Awa

let printf = Printf.printf

let tty_out = Unix.isatty Unix.stdout && Unix.getenv "TERM" <> "dumb"
let colored_or_not cfmt fmt =
  if tty_out then (Printf.sprintf cfmt) else (Printf.sprintf fmt)
let red fmt    = colored_or_not ("\027[31m"^^fmt^^"\027[m") fmt
let green fmt  = colored_or_not ("\027[32m"^^fmt^^"\027[m") fmt
let yellow fmt = colored_or_not ("\027[33m"^^fmt^^"\027[m") fmt
let blue fmt   = colored_or_not ("\027[36m"^^fmt^^"\027[m") fmt

let secret_a = Cstruct.of_string "Pyotr Alexeyevich Kropotkin 1842"
let secret_b = Cstruct.of_string "Buenaventura Durruti - CNT/FAI!!"

let cipher_key_of cipher key =
  let open Nocrypto.Cipher_block.AES in
  let open Cipher in
  match cipher with
  | Aes128_ctr | Aes192_ctr | Aes256_ctr as c ->
    (c, Aes_ctr_key (CTR.of_secret key))
  | Aes128_cbc | Aes192_cbc | Aes256_cbc as c ->
    (c, Aes_cbc_key (CBC.of_secret key))

let hmac_key_of hmac key = Hmac.{ hmac; key; seq = Int32.zero }

let assert_failure x =
  let ok = try
      ignore @@ x ();
      false
    with
      Failure _ -> true
  in
  if not ok then
    failwith "Expected failure exception"

let assert_invalid x =
  let ok = try
      ignore @@ x ();
      false
    with
      Invalid_argument _ -> true
  in
  if not ok then
    invalid_arg "Expected failure exception"

let get_some = function None -> invalid_arg "Expected Some" | Some x -> x

let assert_none = function None -> () | _ -> invalid_arg "Expected None"

let get_ok_s = function
  | Ok x -> x
  | Error s -> invalid_arg s

let t_banner () =
  let good_strings = [
    "SSH-2.0-foobar lalal\r\n";
    "\r\n\r\nSSH-2.0-foobar lalal\r\n";
    "SSH-2.0-foobar lalal lololo\r\n";
    "SSH-2.0-OpenSSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-OpenSSH_6.9\r\n";
    "SSH-2.0-OpenSSH_6.9\r\nSomeCrap After\r\n";
  ]
  in
  List.iter (fun s ->
      match Decode.get_version (Cstruct.of_string s) with
      | Result.Ok (Some s, _) -> ()
      | Result.Ok (None, _) -> failwith "expected some"
      | Result.Error e -> failwith e)
    good_strings;

  let bad_strings = [
    "SSH-2.0\r\n";
    "SSH-1.0-foobar lalal lololo\r\n";
    "SSH-2.0-Open-SSH_6.9\r\n";
    "Some crap before\r\nSSH-2.0-Open-SSH_6.9\r\n";
    "\r\nSSH-2.0-Open-SSH_6.9\r\nSom crap after";
    "SSH-2.0-partiallineomg";
  ]
  in
  List.iter (fun s ->
      match Decode.get_version (Cstruct.of_string s) with
      | Result.Ok (Some _, _) -> failwith "expected none or error"
      | Result.Ok (None, _) -> ()
      | Result.Error e -> ())
    bad_strings

let t_parsing () =
  let open Ssh in
  (*
   * Case 1: Full buff consumed
   *)
  let msg = Ssh_msg_ignore "a" in
  let buf = Packet.plain msg in
  let pkt, rbuf = get_some @@ get_ok_s @@ Packet.get_plain buf in
  let msg2 = get_ok_s @@ Packet.to_msg pkt in
  assert (msg = msg2);
  assert ((Cstruct.len rbuf) = 0);

  (*
   * Case 2: 1 byte left
   *)
  let msg = Ssh_msg_ignore "a" in
  let buf = Packet.plain msg in
  let buf = Cstruct.append buf (Cstruct.of_string "b") in
  let pkt, rbuf = get_some @@ get_ok_s @@ Packet.get_plain buf in
  let msg2 = get_ok_s @@ Packet.to_msg pkt in
  assert (msg = msg2);
  assert ((Cstruct.len rbuf) = 1);

  (* Case 3: Test a zero pkt_len *)
  let buf = Cstruct.create 64 in
  set_pkt_hdr_pkt_len buf 0l;
  set_pkt_hdr_pad_len buf 0;
  let e = get_error (Packet.get_plain buf) in
  assert (e = "get_plain: Bogus pkt len");

  let id msg =
    let buf = Packet.plain msg in
    let pkt, buf = get_some @@ get_ok_s @@ Packet.get_plain buf in
    let msg2 = get_ok_s @@ Packet.to_msg pkt in
    assert ((Cstruct.len buf) = 0);
    match msg, msg2 with
    (* Can't compare Cstruct.t, must unpack and Cstruct.equal () *)
    | Ssh_msg_userauth_request (s1a, s2a, s3a, ba, s4a, ca),
      Ssh_msg_userauth_request (s1b, s2b, s3b, bb, s4b, cb) ->
      assert ((s1a, s2a, s3a, ba, s4a) = (s1b, s2b, s3b, bb, s4b));
      assert (Cstruct.equal ca cb)
    | Ssh_msg_kexdh_reply (pub_rsa1, mpint1, cstring1),
      Ssh_msg_kexdh_reply (pub_rsa2, mpint2, cstring2) ->
      assert (pub_rsa1 = pub_rsa2 && mpint1 = mpint2);
      assert (Cstruct.equal cstring1 cstring2)
    | msg, msg2 -> assert (msg = msg2)
  in
  let long = Int32.of_int 180586 in
  let mpint = Nocrypto.Numeric.Z.of_int 180586 in
  let cstring = Cstruct.of_string "The Conquest of Bread" in
  (* XXX slow *)
  let pub_rsa = Nocrypto.Rsa.(generate 2048 |> pub_of_priv) in
  let l =
    [ Ssh_msg_disconnect (long, "foo", "bar");
      Ssh_msg_ignore "Fora Temer";
      Ssh_msg_unimplemented long;
      Ssh_msg_debug (false, "Fora", "Temer");
      Ssh_msg_service_request "Fora Temer";
      Ssh_msg_service_accept "Ricardo Flores Magon";
      (* Ssh_msg_kexinit foo; *)
      Ssh_msg_kexdh_init mpint;
      Ssh_msg_kexdh_reply (pub_rsa, mpint, cstring);
      Ssh_msg_newkeys;
      Ssh_msg_userauth_request ("a", "b", "c", true, "d", cstring);
      Ssh_msg_userauth_failure (["Fora"; "Temer"], true);
      Ssh_msg_userauth_success;
      Ssh_msg_userauth_banner ("Fora", "Temer");
      (* Ssh_msg_global_request; *)
      (* Ssh_msg_request_success; *)
      (* Ssh_msg_request_failure; *)
      (* Ssh_msg_channel_open; *)
      (* Ssh_msg_channel_open_confirmation; *)
      (* Ssh_msg_channel_open_failure; *)
      Ssh_msg_channel_window_adjust (long, Int32.succ long);
      (* Ssh_msg_channel_data; *)
      (* Ssh_msg_channel_extended_data; *)
      Ssh_msg_channel_eof long;
      Ssh_msg_channel_close long;
      (* Ssh_msg_channel_request; *)
      Ssh_msg_channel_success long;
      Ssh_msg_channel_failure long; ]
  in
  List.iter (fun m -> id m) l

let t_key_exchange () =
  (* Read a pcap file and see if it makes sense. *)
  let file = "test/kex.packet" in
  let fd = Unix.(openfile file [O_RDONLY] 0) in
  let buf = Unix_cstruct.of_fd fd in
  let pkt, rbuf = get_some @@ get_ok_s @@ Packet.get_plain buf in
  let msg = get_ok_s @@ Packet.to_msg pkt in
  let () = match msg with
    | Ssh.Ssh_msg_kexinit kex ->
      (* printf "%s\n%!" (Sexplib.Sexp.to_string_hum (Ssh.sexp_of_kex_pkt kex)); *)
      ()
    | _ -> failwith "Expected Ssh_msg_kexinit"
  in
  Unix.close fd

let t_namelist () =
  let s = ["The";"Conquest";"Of";"Bread"] in
  let buf = Encode.(to_cstruct @@ put_nl s (create ())) in
  assert (Cstruct.len buf = (4 + String.length (String.concat "," s)));
  assert (s = fst (get_ok (Decode.get_nl buf)))

let t_mpint () =
  let assert_byte buf off v =
    assert ((Cstruct.get_uint8 buf off) = v)
  in

  (*
   * Case 1: Make sure zeroes are stripped from the beggining.
   *)
  let head = Cstruct.create 4 in
  let data = Cstruct.create 4 in
  Cstruct.set_uint8 data 0 0x00;
  Cstruct.set_uint8 data 1 0x00;
  Cstruct.set_uint8 data 2 0xff;
  Cstruct.set_uint8 data 3 0x02;
  Cstruct.BE.set_uint32 head 0 (Int32.of_int (Cstruct.len data));
  let mpint = fst @@ get_ok_s @@ Decode.get_mpint (Cstruct.append head data) in
  let buf = Nocrypto.Numeric.Z.to_cstruct_be mpint in
  assert ((Cstruct.len buf) = 2); (* Cuts the first two zeros *)
  assert_byte buf 0 0xff;
  assert_byte buf 1 0x02;

  (*
   * Case 2: Test identity
   *)
  assert (mpint =
          (fst @@ get_ok_s
             (Decode.get_mpint
                (Encode.(to_cstruct @@
                      put_mpint mpint (create ()))))));

  (*
   * Case 3: Test the other way from 1, one zero must be prepended
   * since the first byte is negative (0xff).
   *)
  let buf = Encode.(to_cstruct @@ put_mpint mpint (create ())) in
  (* 4 for header + 1 zero prepended + 2 data*)
  assert ((Cstruct.len buf) = (4 + 1 + 2));
  assert_byte buf 0 0x00;
  assert_byte buf 1 0x00;
  assert_byte buf 2 0x00;
  assert_byte buf 3 0x03;
  assert_byte buf 4 0x00;
  assert_byte buf 5 0xff;
  assert_byte buf 6 0x02;

  (*
   * Case 4: Make sure negative are errors.
   *)
  Cstruct.set_uint8 buf 4 0x80;
  let e = get_error (Decode.get_mpint buf) in
  assert (e = "Negative mpint")

let t_version () =
  (*
   * Case 5: Make sure state transitions are ok.
   *)
  let t, _ = Server.make (Nocrypto.Rsa.generate 2048) in
  let client_version = "SSH-2.0-OpenSSH_6.9\r\n" in
  match Server.pop_msg2 t (Cstruct.of_string client_version) with
  | Error e -> failwith e
  | Ok (t, msg) ->
    match get_some msg with
    | Ssh.Ssh_msg_version v ->
      assert (v = "OpenSSH_6.9");
      let t, _ =  get_ok_s @@ Server.handle_msg t (Ssh.Ssh_msg_version v) in
      assert (t.Server.client_version = (Some "OpenSSH_6.9"))
    | _ -> failwith "Expected Ssh_version"

let t_crypto () =
  let test keys =
    let open Kex in
    let txt = "abcdefghijklmnopqrstuvxz" in
    let msg = Ssh.Ssh_msg_ignore txt in
    let buf_enc, keys_next = Packet.encrypt keys msg in
    let pkt, buf, keys_next2 =
      get_some @@ get_ok_s @@ Packet.decrypt keys buf_enc
    in
    let msg = get_ok_s @@ Packet.to_msg pkt in
    let () = match msg with
      | Ssh.Ssh_msg_ignore s ->
        assert (s = txt)
      | _ -> failwith "bad msg"
    in
    assert ((Cstruct.len buf) = 0)
    (* Side effect below ! *)
    (* Nocrypto.Cipher_block.Counter.add16 keys.Kex.iv 0 Int64.(succ one); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next.Kex.iv); *)
    (* assert (Cstruct.equal keys.Kex.iv keys_next2.Kex.iv) *)
  in
  let make cipher hmac =
    let open Cipher in
    let iv = Cstruct.set_len secret_a 16 in
    let cipher = cipher_key_of cipher secret_a in
    let mac = hmac_key_of hmac secret_a in
    Kex.{ iv; cipher; mac }
  in
  List.iter (fun cipher ->
      List.iter (fun hmac ->
          test (make cipher hmac))
        Hmac.preferred)
    Cipher.preferred

let run_test test =
  let f = fst test in
  let name = snd test in
  printf "%s %-40s%!" (blue "%s" "Test") (yellow "%s" name);
  let () = try f () with
      exn -> printf "%s\n%!" (red "failed");
      raise exn
  in
  printf "%s\n%!" (green "ok")

let all_tests = [
  (t_parsing, "basic parsing");
  (t_banner, "version banner");
  (t_key_exchange, "key exchange");
  (t_namelist, "namelist conversions");
  (t_mpint, "mpint conversions");
  (t_version, "version exchange");
  (t_crypto, "encrypt/decrypt");
]

let _ =
  Nocrypto.Rng.reseed (Cstruct.of_string "180586");
  List.iter run_test all_tests;
