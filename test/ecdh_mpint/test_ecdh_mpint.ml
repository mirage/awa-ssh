open Awa

let ecdh_public_roundtrip () =
  (* We should not mangle Q_C points with 0x00 as their leftmost byte. *)
  let q = String.init 32 (fun i -> if i = 0 then '\000' else Char.chr (i + 1)) in
  let payload msg =
    let b = Buffer.create 64 in
    Wire.put_message b msg;
    let w = Buffer.contents b in
    String.sub w 1 (String.length w - 1)          (* drop the message id *)
  in
  (match Result.get_ok
           (Wire.dh_kexecdh_of_kex Ssh.MSG_KEX_0 (payload (Ssh.Msg_kexecdh_init q)))
   with
   | Ssh.Msg_kexecdh_init q' -> assert (String.equal q q')
   | _ -> failwith "expected Msg_kexecdh_init");

  (* Neither should we mangle the same kind of value as Q_S. *)
  let priv, pub = Mirage_crypto_ec.Ed25519.generate () in
  let signature = Hostkey.sign Hostkey.Ed25519 (Hostkey.Ed25519_priv priv) "h" in
  let reply =
    Ssh.Msg_kexecdh_reply
      (Hostkey.Ed25519_pub pub, q, (Hostkey.Ed25519, signature))
  in
  match Result.get_ok (Wire.dh_kexecdh_of_kex Ssh.MSG_KEX_1 (payload reply)) with
  | Ssh.Msg_kexecdh_reply (_, q', _) -> assert (String.equal q q')
  | _ -> failwith "expected Msg_kexecdh_reply"

(* Every mpint SSH sends is a modulus, generator, group element or key
   component, none of which are negative. Check here that we refuse them
   in both directions as a precaution. *)
let mpint_sign () =
  let wire bytes =
    let b = Buffer.create 16 in
    Wire.put_uint32 b (Int32.of_int (String.length bytes));
    Buffer.add_string b bytes;
    Buffer.contents b
  in

  (* Received: negatives refused, a padded positive still accepted. *)
  assert (Result.is_error (Wire.get_mpint (wire "\xed\xcc") 0));   (* -1234 *)
  assert (Result.is_error (Wire.get_mpint (wire "\xff") 0));        (* -1 *)
  assert (fst (Result.get_ok (Wire.get_mpint (wire "\x00\x80") 0)) = Z.of_int 128);

  (* Sent: refused rather than silently turned into another number. *)
  assert (match Wire.put_mpint (Buffer.create 16) (Z.of_int (-1234)) with
          | exception Invalid_argument _ -> true
          | () -> false);
  let b = Buffer.create 16 in
  Wire.put_mpint b (Z.of_int 1234);
  assert (String.equal (Buffer.contents b) "\x00\x00\x00\x02\x04\xd2")

let () =
  Mirage_crypto_rng_unix.use_default ();
  ecdh_public_roundtrip ();
  mpint_sign ()
