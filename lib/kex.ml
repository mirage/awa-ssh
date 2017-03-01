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

open Sexplib.Conv
open Rresult.R
open Util
open Ssh
open Nocrypto

type algorithm =
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1

let algorithm_of_string = function
  | "diffie-hellman-group14-sha1" -> ok Diffie_hellman_group14_sha1
  | "diffie-hellman-group1-sha1"  -> ok Diffie_hellman_group1_sha1
  | s -> error ("Unknown kex_algorithm " ^ s)

let algorithm_to_string = function
  | Diffie_hellman_group14_sha1 -> "diffie-hellman-group14-sha1"
  | Diffie_hellman_group1_sha1  -> "diffie-hellman-group1-sha1"

let group_of_algorithm = function
  | Diffie_hellman_group14_sha1 -> Nocrypto.Dh.Group.oakley_2
  | Diffie_hellman_group1_sha1  -> Nocrypto.Dh.Group.oakley_14

let preferred = [ Diffie_hellman_group14_sha1; Diffie_hellman_group1_sha1 ]

let make_pkt () =
  { cookie = Nocrypto.Rng.generate 16;
    kex_algorithms = List.map algorithm_to_string preferred;
    server_host_key_algorithms = [ "ssh-rsa" ];
    encryption_algorithms_ctos = List.map Cipher.to_string Cipher.preferred;
    encryption_algorithms_stoc = List.map Cipher.to_string Cipher.preferred;
    mac_algorithms_ctos = List.map Hmac.to_string Hmac.preferred;
    mac_algorithms_stoc = List.map Hmac.to_string Hmac.preferred;
    compression_algorithms_ctos = [ "none" ];
    compression_algorithms_stoc = [ "none" ];
    languages_ctos = [];
    languages_stoc = [];
    first_kex_packet_follows = false }

type negotiation = {
  kex_algorithm : algorithm;
  server_host_key_algorithm : server_host_key_algorithm;
  encryption_algorithm_ctos : Cipher.t;
  encryption_algorithm_stoc : Cipher.t;
  mac_algorithm_ctos : Hmac.t;
  mac_algorithm_stoc : Hmac.t;
  compression_algorithm_ctos : compression_algorithm;
  compression_algorithm_stoc : compression_algorithm;
}

let keylen_needed (neg : negotiation) =
  let ctos = neg.encryption_algorithm_ctos in
  let stoc = neg.encryption_algorithm_stoc in
  max (Cipher.iv_len ctos)    @@ max (Cipher.iv_len stoc) @@
  max (Cipher.block_len ctos) @@ Cipher.block_len stoc

let negotiate ~s ~c =
  let pick_common f ~s ~c e =
    try
      f (List.find (fun x -> List.mem x s) c)
    with
      Not_found -> error e
  in
  pick_common
    algorithm_of_string
    ~s:s.kex_algorithms
    ~c:c.kex_algorithms
    "Can't agree on kex algorithm"
  >>= fun kex_algorithm ->
  pick_common
    server_host_key_algorithm_of_string
    ~s:s.server_host_key_algorithms
    ~c:c.server_host_key_algorithms
    "Can't agree on server host key algorithm"
  >>= fun server_host_key_algorithm ->
  pick_common
    Cipher.of_string
    ~s:s.encryption_algorithms_ctos
    ~c:c.encryption_algorithms_ctos
    "Can't agree on encryption algorithm client to server"
  >>= fun encryption_algorithm_ctos ->
  pick_common
    Cipher.of_string
    ~s:s.encryption_algorithms_stoc
    ~c:c.encryption_algorithms_stoc
    "Can't agree on encryption algorithm server to client"
  >>= fun encryption_algorithm_stoc ->
  pick_common
    Hmac.of_string
    ~s:s.mac_algorithms_ctos
    ~c:c.mac_algorithms_ctos
    "Can't agree on mac algorithm client to server"
  >>= fun mac_algorithm_ctos ->
  pick_common
    Hmac.of_string
    ~s:s.mac_algorithms_stoc
    ~c:c.mac_algorithms_stoc
    "Can't agree on mac algorithm server to client"
  >>= fun mac_algorithm_stoc ->
  pick_common
    compression_algorithm_of_string
    ~s:s.compression_algorithms_ctos
    ~c:c.compression_algorithms_ctos
    "Can't agree on compression algorithm client to server"
  >>= fun compression_algorithm_ctos ->
  pick_common
    compression_algorithm_of_string
    ~s:s.compression_algorithms_stoc
    ~c:c.compression_algorithms_stoc
    "Can't agree on compression algorithm server to client"
  >>= fun compression_algorithm_stoc ->
  ok { kex_algorithm;
       server_host_key_algorithm;
       encryption_algorithm_ctos;
       encryption_algorithm_stoc;
       mac_algorithm_ctos;
       mac_algorithm_stoc;
       compression_algorithm_ctos;
       compression_algorithm_stoc }
      (* ignore language_ctos and language_stoc *)

type keys = {
  iv     : Cstruct.t;   (* Initial IV *)
  cipher : Cipher.key; (* Encryption key *)
  mac    : Hmac.key;   (* Integrity key *)
}

let derive_keys digestv k h session_id neg =
  let need = keylen_needed neg in
  let cipher_ctos = neg.encryption_algorithm_ctos in
  let cipher_stoc = neg.encryption_algorithm_stoc in
  let mac_ctos = neg.mac_algorithm_ctos in
  let mac_stoc = neg.mac_algorithm_stoc in
  let k = Encode.(to_cstruct @@ put_mpint k (create ())) in
  let x = Cstruct.create 1 in
  let rec expand kn =
    if (Cstruct.len kn) >= need then
      kn
    else
      expand (digestv [k; h; kn])
  in
  let hash ch =
    Cstruct.set_char x 0 ch;
    expand (digestv [k; h; x; session_id])
  in
  let key_of cipher h =
    let open Nocrypto.Cipher_block in
    let open Cipher in
    match cipher with
    | Aes128_ctr | Aes192_ctr | Aes256_ctr ->
      (cipher, Aes_ctr_key (AES.CTR.of_secret h))
    | Aes128_cbc | Aes192_cbc | Aes256_cbc ->
      (cipher, Aes_cbc_key (AES.CBC.of_secret h))
  in
  let ctos = { iv     = hash 'A';
               cipher = hash 'C' |> key_of cipher_ctos;
               mac    = (mac_ctos, hash 'E'); }
  in
  let stoc = { iv     = hash 'B';
               cipher = hash 'D' |> key_of cipher_stoc;
               mac    = (mac_stoc, hash 'F'); }
  in
  (ctos, stoc)


module Dh = struct

  let derive_keys = derive_keys Nocrypto.Hash.SHA1.digestv

  let compute_hash ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k =
    let open Encode in
    put_cstring v_c (create ()) |>
    put_cstring v_s |>
    put_cstring i_c |>
    put_cstring i_s |>
    put_mpint e |>
    put_mpint f |>
    put_mpint k |>
    to_cstruct |>
    Hash.SHA1.digest

  let generate alg peer_pub =
    let g = group_of_algorithm alg in
    let secret, my_pub = Dh.gen_key g in
    guard_some
      (Nocrypto.Dh.shared g secret (Numeric.Z.to_cstruct_be peer_pub))
      "Can't compute shared secret"
    >>= fun shared ->
    (* secret is y, my_pub is f or e, shared is k *)
    ok (secret, Numeric.Z.of_cstruct_be my_pub, Numeric.Z.of_cstruct_be shared)

end
