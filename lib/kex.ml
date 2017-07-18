(*
 * Copyright (c) 2017 Christiano F. Haesbaert <haesbaert@haesbaert.org>
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

open Rresult.R
open Util
open Ssh
open Nocrypto

type server_host_key_alg =
  | Ssh_rsa

let server_host_key_alg_of_string = function
  | "ssh-rsa" -> ok Ssh_rsa
  | s -> error ("Unknown server host key algorithm " ^ s)

let server_host_key_alg_to_string = function
  | Ssh_rsa -> "ssh-rsa"

type compression_alg =
  | Nothing                        (* Can't use None :-D *)

let compression_alg_of_string = function
  | "none" -> ok Nothing
  | s -> error ("Unknown compression algorithm " ^ s)

let compression_alg_to_string = function
  | Nothing -> "none"

type alg =
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1

let alg_of_string = function
  | "diffie-hellman-group14-sha1" -> ok Diffie_hellman_group14_sha1
  | "diffie-hellman-group1-sha1"  -> ok Diffie_hellman_group1_sha1
  | s -> error ("Unknown kex_alg " ^ s)

let alg_to_string = function
  | Diffie_hellman_group14_sha1 -> "diffie-hellman-group14-sha1"
  | Diffie_hellman_group1_sha1  -> "diffie-hellman-group1-sha1"

let group_of_alg = function
  | Diffie_hellman_group14_sha1 -> Dh.Group.oakley_14
  | Diffie_hellman_group1_sha1  -> Dh.Group.oakley_2

let preferred = [ Diffie_hellman_group14_sha1; Diffie_hellman_group1_sha1 ]

let make_kexinit () =
  { cookie = Rng.generate 16;
    kex_algs = List.map alg_to_string preferred;
    server_host_key_algs = [ "ssh-rsa" ];
    encryption_algs_ctos = List.map Cipher.to_string Cipher.preferred;
    encryption_algs_stoc = List.map Cipher.to_string Cipher.preferred;
    mac_algs_ctos = List.map Hmac.to_string Hmac.preferred;
    mac_algs_stoc = List.map Hmac.to_string Hmac.preferred;
    compression_algs_ctos = [ "none" ];
    compression_algs_stoc = [ "none" ];
    languages_ctos = [];
    languages_stoc = [];
    first_kex_packet_follows = false;
    input_buf = None }

type negotiation = {
  kex_alg              : alg;
  server_host_key_alg  : server_host_key_alg;
  encryption_alg_ctos  : Cipher.t;
  encryption_alg_stoc  : Cipher.t;
  mac_alg_ctos         : Hmac.t;
  mac_alg_stoc         : Hmac.t;
  compression_alg_ctos : compression_alg;
  compression_alg_stoc : compression_alg;
}

let guessed_right ~s ~c =
  let compare_hd a b =
    match (a, b) with
    | [], [] -> true
    | [], _  -> false
    | _, []  -> false
    | x :: _, y :: _ -> x = y
  in
  compare_hd s.kex_algs c.kex_algs &&
  compare_hd s.server_host_key_algs c.server_host_key_algs &&
  compare_hd s.encryption_algs_ctos c.encryption_algs_ctos &&
  compare_hd s.encryption_algs_stoc c.encryption_algs_stoc &&
  compare_hd s.mac_algs_ctos c.mac_algs_ctos &&
  compare_hd s.mac_algs_stoc c.mac_algs_stoc &&
  compare_hd s.compression_algs_ctos c.compression_algs_ctos &&
  compare_hd s.compression_algs_stoc c.compression_algs_stoc

let negotiate ~s ~c =
  let pick_common f ~s ~c e =
    try
      f (List.find (fun x -> List.mem x s) c)
    with
      Not_found -> error e
  in
  pick_common
    alg_of_string
    ~s:s.kex_algs
    ~c:c.kex_algs
    "Can't agree on kex algorithm"
  >>= fun kex_alg ->
  pick_common
    server_host_key_alg_of_string
    ~s:s.server_host_key_algs
    ~c:c.server_host_key_algs
    "Can't agree on server host key algorithm"
  >>= fun server_host_key_alg ->
  pick_common
    Cipher.of_string
    ~s:s.encryption_algs_ctos
    ~c:c.encryption_algs_ctos
    "Can't agree on encryption algorithm client to server"
  >>= fun encryption_alg_ctos ->
  pick_common
    Cipher.of_string
    ~s:s.encryption_algs_stoc
    ~c:c.encryption_algs_stoc
    "Can't agree on encryption algorithm server to client"
  >>= fun encryption_alg_stoc ->
  pick_common
    Hmac.of_string
    ~s:s.mac_algs_ctos
    ~c:c.mac_algs_ctos
    "Can't agree on mac algorithm client to server"
  >>= fun mac_alg_ctos ->
  pick_common
    Hmac.of_string
    ~s:s.mac_algs_stoc
    ~c:c.mac_algs_stoc
    "Can't agree on mac algorithm server to client"
  >>= fun mac_alg_stoc ->
  pick_common
    compression_alg_of_string
    ~s:s.compression_algs_ctos
    ~c:c.compression_algs_ctos
    "Can't agree on compression algorithm client to server"
  >>= fun compression_alg_ctos ->
  pick_common
    compression_alg_of_string
    ~s:s.compression_algs_stoc
    ~c:c.compression_algs_stoc
    "Can't agree on compression algorithm server to client"
  >>= fun compression_alg_stoc ->
  ok { kex_alg;
       server_host_key_alg;
       encryption_alg_ctos;
       encryption_alg_stoc;
       mac_alg_ctos;
       mac_alg_stoc;
       compression_alg_ctos;
       compression_alg_stoc }
      (* ignore language_ctos and language_stoc *)

type keys = {
  iv     : Cstruct.t;  (* Initial IV *)
  cipher : Cipher.key; (* Encryption key *)
  mac    : Hmac.key;   (* Integrity key *)
}

let plaintext_keys = {
  iv = Cstruct.create 0;
  cipher = Cipher.(Plaintext, Plaintext_key);
  mac = Hmac.{ hmac = Plaintext;
               key = Cstruct.create 0;
               seq = Int32.zero }
}

let derive_keys digestv k h session_id neg =
  let cipher_ctos = neg.encryption_alg_ctos in
  let cipher_stoc = neg.encryption_alg_stoc in
  let mac_ctos = neg.mac_alg_ctos in
  let mac_stoc = neg.mac_alg_stoc in
  let k = Wire.(Dbuf.to_cstruct @@ put_mpint k (Dbuf.create ())) in
  let hash ch need =
    let rec expand kn =
      if (Cstruct.len kn) >= need then
        kn
      else
        let kn' = digestv [k; h; kn] in
        expand (Cstruct.append kn kn')
    in
    let x = Cstruct.create 1 in
    Cstruct.set_char x 0 ch;
    let k1 = digestv [k; h; x; session_id] in
    Cstruct.set_len (expand k1) need
  in
  let key_of cipher secret =
    let open Cipher_block in
    let open Cipher in
    match cipher with
    | Plaintext -> failwith "Deriving plaintext"
    | Aes128_ctr | Aes192_ctr | Aes256_ctr ->
      cipher, Aes_ctr_key (AES.CTR.of_secret secret)
    | Aes128_cbc | Aes192_cbc | Aes256_cbc ->
      cipher, Aes_cbc_key (AES.CBC.of_secret secret)
  in
  let ctos = {
    iv     = hash 'A' (Cipher.iv_len cipher_ctos);
    cipher = hash 'C' (Cipher.key_len cipher_ctos) |> key_of cipher_ctos;
    mac    = Hmac.{ hmac = mac_ctos;
                    key = hash 'E' (key_len mac_ctos);
                    seq = Int32.zero }
  }
  in
  let stoc = {
    iv     = hash 'B' (Cipher.iv_len cipher_stoc);
    cipher = hash 'D' (Cipher.key_len cipher_stoc) |> key_of cipher_stoc;
    mac    = Hmac.{ hmac = mac_stoc;
                    key = hash 'F' (key_len mac_stoc);
                    seq = Int32.zero }
  }
  in
  (ctos, stoc)

module Dh = struct

  let derive_keys = derive_keys Hash.SHA1.digestv

  let compute_hash ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k =
    let open Wire in
    put_cstring v_c (Dbuf.create ()) |>
    put_cstring v_s |>
    put_cstring i_c |>
    put_cstring i_s |>
    put_cstring k_s |>
    put_mpint e |>
    put_mpint f |>
    put_mpint k |>
    Dbuf.to_cstruct |>
    Hash.SHA1.digest

  let generate alg peer_pub =
    let g = group_of_alg alg in
    let secret, my_pub = Dh.gen_key g in
    guard_some
      (Dh.shared g secret (Numeric.Z.to_cstruct_be peer_pub))
      "Can't compute shared secret"
    >>= fun shared ->
    (* secret is y, my_pub is f or e, shared is k *)
    ok Numeric.Z.(secret, of_cstruct_be my_pub, of_cstruct_be shared)

end
