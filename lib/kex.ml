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

open Util
open Ssh

type compression_alg =
  | Nothing                        (* Can't use None :-D *)

let compression_alg_of_string = function
  | "none" -> Ok Nothing
  | s -> Error ("Unknown compression algorithm " ^ s)

let compression_alg_to_string = function
  | Nothing -> "none"

type alg =
  | Diffie_hellman_group_exchange_sha256
  | Diffie_hellman_group14_sha256
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1
  | Diffie_hellman_group_exchange_sha1
  | Curve25519_sha256
  | Ecdh_sha2_nistp256
  | Ecdh_sha2_nistp384
  | Ecdh_sha2_nistp521

let is_rfc4419 = function
  | Diffie_hellman_group_exchange_sha256
  | Diffie_hellman_group_exchange_sha1 -> true
  | Diffie_hellman_group14_sha256
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1
  | Curve25519_sha256
  | Ecdh_sha2_nistp256
  | Ecdh_sha2_nistp384
  | Ecdh_sha2_nistp521 -> false

let is_finite_field = function
  | Diffie_hellman_group_exchange_sha256
  | Diffie_hellman_group_exchange_sha1
  | Diffie_hellman_group14_sha256
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1 -> true
  | Curve25519_sha256
  | Ecdh_sha2_nistp256
  | Ecdh_sha2_nistp384
  | Ecdh_sha2_nistp521 -> false

let alg_of_string = function
  | "diffie-hellman-group-exchange-sha256" -> Ok Diffie_hellman_group_exchange_sha256
  | "diffie-hellman-group-exchange-sha1" -> Ok Diffie_hellman_group_exchange_sha1
  | "diffie-hellman-group14-sha256" -> Ok Diffie_hellman_group14_sha256
  | "diffie-hellman-group14-sha1" -> Ok Diffie_hellman_group14_sha1
  | "diffie-hellman-group1-sha1" -> Ok Diffie_hellman_group1_sha1
  | "curve25519-sha256" -> Ok Curve25519_sha256
  | "ecdh-sha2-nistp256" -> Ok Ecdh_sha2_nistp256
  | "ecdh-sha2-nistp384" -> Ok Ecdh_sha2_nistp384
  | "ecdh-sha2-nistp521" -> Ok Ecdh_sha2_nistp521
  | s -> Error ("Unknown kex_alg " ^ s)

let alg_to_string = function
  | Diffie_hellman_group_exchange_sha256 -> "diffie-hellman-group-exchange-sha256"
  | Diffie_hellman_group_exchange_sha1 -> "diffie-hellman-group-exchange-sha1"
  | Diffie_hellman_group14_sha256 -> "diffie-hellman-group14-sha256"
  | Diffie_hellman_group14_sha1 -> "diffie-hellman-group14-sha1"
  | Diffie_hellman_group1_sha1  -> "diffie-hellman-group1-sha1"
  | Curve25519_sha256 -> "curve25519-sha256"
  | Ecdh_sha2_nistp256 -> "ecdh-sha2-nistp256"
  | Ecdh_sha2_nistp384 -> "ecdh-sha2-nistp384"
  | Ecdh_sha2_nistp521 -> "ecdh-sha2-nistp521"

let group_of_alg = function
  | Diffie_hellman_group14_sha256 -> Mirage_crypto_pk.Dh.Group.oakley_14
  | Diffie_hellman_group14_sha1 -> Mirage_crypto_pk.Dh.Group.oakley_14
  | Diffie_hellman_group1_sha1  -> Mirage_crypto_pk.Dh.Group.oakley_2
  | Diffie_hellman_group_exchange_sha1
  | Diffie_hellman_group_exchange_sha256
  | Curve25519_sha256
  | Ecdh_sha2_nistp256
  | Ecdh_sha2_nistp384
  | Ecdh_sha2_nistp521 -> assert false

let hash_of_alg = function
  | Diffie_hellman_group_exchange_sha256
  | Diffie_hellman_group14_sha256
  | Curve25519_sha256 -> Mirage_crypto.Hash.module_of `SHA256
  | Diffie_hellman_group_exchange_sha1
  | Diffie_hellman_group14_sha1
  | Diffie_hellman_group1_sha1 -> Mirage_crypto.Hash.module_of `SHA1
  | Ecdh_sha2_nistp256 -> Mirage_crypto.Hash.module_of `SHA256
  | Ecdh_sha2_nistp384 -> Mirage_crypto.Hash.module_of `SHA384
  | Ecdh_sha2_nistp521 -> Mirage_crypto.Hash.module_of `SHA512

let client_supported =
  [ Curve25519_sha256 ;
    Ecdh_sha2_nistp256 ; Ecdh_sha2_nistp384 ; Ecdh_sha2_nistp521 ;
    Diffie_hellman_group14_sha256 ; Diffie_hellman_group_exchange_sha256 ;
    Diffie_hellman_group14_sha1 ; Diffie_hellman_group1_sha1 ;
    Diffie_hellman_group_exchange_sha1 ]

let server_supported =
  [ Diffie_hellman_group14_sha256 ; Diffie_hellman_group14_sha1 ;
    Diffie_hellman_group1_sha1 ]

let make_kexinit host_key_algs algs () =
  let k =
    { cookie = Mirage_crypto_rng.generate 16;
      kex_algs = List.map alg_to_string algs;
      server_host_key_algs = List.map Hostkey.alg_to_string host_key_algs;
      encryption_algs_ctos = List.map Cipher.to_string Cipher.preferred;
      encryption_algs_stoc = List.map Cipher.to_string Cipher.preferred;
      mac_algs_ctos = List.map Hmac.to_string Hmac.preferred;
      mac_algs_stoc = List.map Hmac.to_string Hmac.preferred;
      compression_algs_ctos = [ "none" ];
      compression_algs_stoc = [ "none" ];
      languages_ctos = [];
      languages_stoc = [];
      first_kex_packet_follows = false;
      rawkex = Cstruct.create 0 }
  in
  (* Patch k with rawkex, for completion sake *)
  { k with rawkex = Wire.blob_of_kexinit k }

type negotiation = {
  kex_alg              : alg;
  server_host_key_alg  : Hostkey.alg;
  encryption_alg_ctos  : Cipher.t;
  encryption_alg_stoc  : Cipher.t;
  mac_alg_ctos         : Hmac.t;
  mac_alg_stoc         : Hmac.t;
  compression_alg_ctos : compression_alg;
  compression_alg_stoc : compression_alg;
}

let pp_negotiation ppf neg =
  Format.fprintf ppf "kex %s host key alg %s@.enc ctos %s stoc %s@.mac ctos %s stoc %s@.compression ctos %s stoc %s"
    (alg_to_string neg.kex_alg) (Hostkey.alg_to_string neg.server_host_key_alg)
    (Cipher.to_string neg.encryption_alg_ctos) (Cipher.to_string neg.encryption_alg_stoc)
    (Hmac.to_string neg.mac_alg_ctos) (Hmac.to_string neg.mac_alg_stoc)
    (compression_alg_to_string neg.compression_alg_ctos)
    (compression_alg_to_string neg.compression_alg_stoc)

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

(* negotiate / pick_common should prefer _ours_ over _theirs_ (well, the
   client decides ultimately (by sending the next message), no?) *)
let negotiate ~s ~c =
  let pick_common f ~s ~c e =
    try
      f (List.find (fun x -> List.mem x s) c)
    with
      Not_found -> Error e
  in
  let* kex_alg =
    pick_common
      alg_of_string
      ~s:s.kex_algs
      ~c:c.kex_algs
      "Can't agree on kex algorithm"
  in
  let* server_host_key_alg =
    pick_common
      Hostkey.alg_of_string
      ~s:s.server_host_key_algs
      ~c:c.server_host_key_algs
      "Can't agree on server host key algorithm"
  in
  let* encryption_alg_ctos =
    pick_common
      Cipher.of_string
      ~s:s.encryption_algs_ctos
      ~c:c.encryption_algs_ctos
      "Can't agree on encryption algorithm client to server"
  in
  let* encryption_alg_stoc =
    pick_common
      Cipher.of_string
      ~s:s.encryption_algs_stoc
      ~c:c.encryption_algs_stoc
      "Can't agree on encryption algorithm server to client"
  in
  let* mac_alg_ctos =
    if Cipher.aead encryption_alg_ctos then
      Ok Hmac.Plaintext
    else
      pick_common
        Hmac.of_string
        ~s:s.mac_algs_ctos
        ~c:c.mac_algs_ctos
        "Can't agree on mac algorithm client to server"
  in
  let* mac_alg_stoc =
    if Cipher.aead encryption_alg_stoc then
      Ok Hmac.Plaintext
    else
      pick_common
        Hmac.of_string
        ~s:s.mac_algs_stoc
        ~c:c.mac_algs_stoc
        "Can't agree on mac algorithm server to client"
  in
  let* compression_alg_ctos =
    pick_common
      compression_alg_of_string
      ~s:s.compression_algs_ctos
      ~c:c.compression_algs_ctos
      "Can't agree on compression algorithm client to server"
  in
  let* compression_alg_stoc =
    pick_common
      compression_alg_of_string
      ~s:s.compression_algs_stoc
      ~c:c.compression_algs_stoc
      "Can't agree on compression algorithm server to client"
  in
  (* XXX make sure it's not plaintext here *)
  Ok { kex_alg;
       server_host_key_alg;
       encryption_alg_ctos;
       encryption_alg_stoc;
       mac_alg_ctos;
       mac_alg_stoc;
       compression_alg_ctos;
       compression_alg_stoc }
      (* ignore language_ctos and language_stoc *)

type keys = {
  cipher   : Cipher.key; (* Encryption key *)
  mac      : Hmac.key;   (* Integrity key *)
  seq      : int32;      (* Sequence number *)
  tx_rx    : int64;      (* Transmitted or Received bytes with this key *)
}

let make_plaintext () =
  { cipher = Cipher.{ cipher = Plaintext;
                      cipher_key = Plaintext_key };
    mac = Hmac.{ hmac = Plaintext;
                 key = Cstruct.create 0 };
    seq = Int32.zero ;
    tx_rx = Int64.zero }

let is_plaintext keys =
  let cipher = keys.cipher.Cipher.cipher in
  let hmac = keys.mac.Hmac.hmac in
  match cipher, hmac with
  | Cipher.Plaintext, Hmac.Plaintext -> true
  | Cipher.Plaintext, _ ->
       invalid_arg "Cipher is plaintext, abort at all costs!"
  | cipher_alg, Hmac.Plaintext ->
    (* with AEAD it's ok to have Hmac.Plaintext, see func negotiate *)
    if Cipher.aead cipher_alg then
      false
    else
      invalid_arg "Cipher is not AEAD and Hmac is plaintext, abort at all costs!"
  | _, _ -> false

let is_keyed keys = not (is_plaintext keys)

(* For how many bytes is this key good ? (in bytes) *)
let one_GB = 1000000000L
let one_minute_ns = 60000000000L

(* How long should we use the same key ? (in ns) *)
let keys_lifespan = Int64.mul 60L one_minute_ns |> Mtime.Span.of_uint64_ns

let should_rekey tx eol now =
  (* If we overflow signed 64bit, something is really wrong *)
  assert (tx >= Int64.zero);
  let expired = Mtime.is_later now ~than:eol in
  (tx >= one_GB || expired)

let derive_keys digesti k h session_id neg now =
  let cipher_ctos = neg.encryption_alg_ctos in
  let cipher_stoc = neg.encryption_alg_stoc in
  let mac_ctos = neg.mac_alg_ctos in
  let mac_stoc = neg.mac_alg_stoc in
  let k = Wire.(Dbuf.to_cstruct @@ put_mpint k (Dbuf.create ())) in
  let hash ch need =
    let rec expand kn =
      if (Cstruct.length kn) >= need then
        kn
      else
        let kn' = digesti (fun f -> List.iter f [k; h; kn]) in
        expand (Cstruct.append kn kn')
    in
    let x = Cstruct.create 1 in
    Cstruct.set_char x 0 ch;
    let k1 = digesti (fun f -> List.iter f [k; h; x; session_id]) in
    Cstruct.sub (expand k1) 0 need
  in
  let key_of cipher iv secret =
    let open Mirage_crypto.Cipher_block in
    let open Cipher in
    match cipher with
    | Plaintext -> invalid_arg "Deriving plaintext, abort at all costs"
    | Aes128_ctr | Aes192_ctr | Aes256_ctr ->
      let iv = AES.CTR.ctr_of_cstruct iv in
      { cipher;
        cipher_key = Aes_ctr_key ((AES.CTR.of_secret secret), iv) }
    | Aes128_cbc | Aes192_cbc | Aes256_cbc ->
      { cipher;
        cipher_key = Aes_cbc_key ((AES.CBC.of_secret secret), iv) }
    | Chacha20_poly1305 ->
      assert (Cstruct.length secret = 64);
      let d, l = Cstruct.split secret 32 in
      let lkey = Mirage_crypto.Chacha20.of_secret l
      and key = Mirage_crypto.Chacha20.of_secret d
      in
      { cipher; cipher_key = Chacha20_poly1305_key (lkey, key) }
  in
  (* Build new keys_ctos keys *)
  let ctos_iv = hash 'A' (Cipher.iv_len cipher_ctos) in
  let ctos = { cipher = hash 'C' (Cipher.key_len cipher_ctos) |>
                        key_of cipher_ctos ctos_iv;
               mac = Hmac.{ hmac = mac_ctos;
                            key = hash 'E' (key_len mac_ctos) };
               seq = Int32.zero;
               tx_rx = Int64.zero }
  in
  (* Build new stoc keys *)
  let stoc_iv = hash 'B' (Cipher.iv_len cipher_stoc) in
  let stoc = { cipher = hash 'D' (Cipher.key_len cipher_stoc) |>
                        key_of cipher_stoc stoc_iv;
               mac = Hmac.{ hmac = mac_stoc;
                            key = hash 'F' (key_len mac_stoc) };
               seq = Int32.zero;
               tx_rx = Int64.zero }
  in
  let* eol = guard_some (Mtime.add_span now keys_lifespan) "key eol overflow" in
  Ok (ctos, stoc, eol)

module Dh = struct

  let derive_keys k h session_id neg now =
    let (module H) = hash_of_alg neg.kex_alg in
    derive_keys H.digesti k h session_id neg now

  let compute_hash ?(signed = false) neg ~v_c ~v_s ~i_c ~i_s ~k_s ~e ~f ~k =
    let (module H) = hash_of_alg neg.kex_alg in
    let open Wire in
    put_cstring (Cstruct.of_string v_c) (Dbuf.create ()) |>
    put_cstring (Cstruct.of_string v_s) |>
    put_cstring i_c |>
    put_cstring i_s |>
    put_cstring (Wire.blob_of_pubkey k_s) |>
    put_mpint ~signed e |>
    put_mpint ~signed f |>
    put_mpint k |>
    Dbuf.to_cstruct |>
    H.digest

  let compute_hash_gex neg ~v_c ~v_s ~i_c ~i_s ~k_s ~min ~n ~max ~p ~g ~e ~f ~k =
    let (module H) = hash_of_alg neg.kex_alg in
    let open Wire in
    put_cstring (Cstruct.of_string v_c) (Dbuf.create ()) |>
    put_cstring (Cstruct.of_string v_s) |>
    put_cstring i_c |>
    put_cstring i_s |>
    put_cstring (Wire.blob_of_pubkey k_s) |>
    put_uint32 min |>
    put_uint32 n |>
    put_uint32 max |>
    put_mpint p |>
    put_mpint g |>
    put_mpint e |>
    put_mpint f |>
    put_mpint k |>
    Dbuf.to_cstruct |>
    H.digest

  let secret_pub alg =
    let secret, pub = Mirage_crypto_pk.Dh.gen_key (group_of_alg alg) in
    secret, Mirage_crypto_pk.Z_extra.of_cstruct_be pub

  let shared secret recv =
    let r = Mirage_crypto_pk.Z_extra.to_cstruct_be recv in
    let* shared =
      guard_some (Mirage_crypto_pk.Dh.shared secret r)
        "Can't compute shared secret"
    in
    Ok (Mirage_crypto_pk.Z_extra.of_cstruct_be shared)

  let ec_secret_pub = function
    | Curve25519_sha256 ->
      let secret, pub = Mirage_crypto_ec.X25519.gen_key () in
      `Ed25519 secret, Mirage_crypto_pk.Z_extra.of_cstruct_be pub
    | Ecdh_sha2_nistp256 ->
      let secret, pub = Mirage_crypto_ec.P256.Dh.gen_key () in
      `P256 secret, Mirage_crypto_pk.Z_extra.of_cstruct_be pub
    | Ecdh_sha2_nistp384 ->
      let secret, pub = Mirage_crypto_ec.P384.Dh.gen_key () in
      `P384 secret, Mirage_crypto_pk.Z_extra.of_cstruct_be pub
    | Ecdh_sha2_nistp521 ->
      let secret, pub = Mirage_crypto_ec.P521.Dh.gen_key () in
      `P521 secret, Mirage_crypto_pk.Z_extra.of_cstruct_be pub
    | _ -> assert false

  let ec_shared secret recv =
    let r = Mirage_crypto_pk.Z_extra.to_cstruct_be recv in
    let* shared =
      Result.map_error
        (Fmt.to_to_string Mirage_crypto_ec.pp_error)
        (match secret with
         | `Ed25519 secret -> Mirage_crypto_ec.X25519.key_exchange secret r
         | `P256 secret -> Mirage_crypto_ec.P256.Dh.key_exchange secret r
         | `P384 secret -> Mirage_crypto_ec.P384.Dh.key_exchange secret r
         | `P521 secret -> Mirage_crypto_ec.P521.Dh.key_exchange secret r)
    in
    Ok (Mirage_crypto_pk.Z_extra.of_cstruct_be shared)

  let generate alg peer_pub =
    let secret, my_pub = secret_pub alg in
    let* shared = shared secret peer_pub in
    (* my_pub is f or e, shared is k *)
    Ok (my_pub, shared)

end
