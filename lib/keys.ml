
open Rresult.R.Infix

let src = Logs.Src.create "awa.authenticator" ~doc:"AWA authenticator"
module Log = (val Logs.src_log src : Logs.LOG)

type authenticator = [
  | `No_authentication
  | `Key of Hostkey.pub
  | `Fingerprint of string
]

let hostkey_matches a key =
  match a with
  | `No_authentication ->
    Log.warn (fun m -> m "NO AUTHENTICATOR");
    true
  | `Key pub' ->
    if key = pub' then begin
      Log.app (fun m -> m "host key verification successful!");
      true
    end else begin
      Log.err (fun m -> m "host key verification failed");
      false
    end
  | `Fingerprint s ->
    let hash = Mirage_crypto.Hash.SHA256.digest (Wire.blob_of_pubkey key) in
    Log.app (fun m -> m "authenticating server fingerprint SHA256:%s"
                 (Base64.encode_string ~pad:false (Cstruct.to_string hash)));
    if Cstruct.(equal (Cstruct.of_string s) hash) then begin
      Log.app (fun m -> m "host fingerprint verification successful!");
      true
    end else begin
      Log.err (fun m -> m "host fingerprint verification failed");
      false
    end

let authenticator_of_string str =
  if str = "" then
    Ok `No_authentication
  else
    match Astring.String.cut ~sep:":" str with
    | Some ("SHA256", fp) ->
      begin match Base64.decode ~pad:false fp with
        | Error (`Msg m) ->
          Error ("invalid authenticator (bad b64 in fingerprint): " ^ m)
        | Ok fp -> Ok (`Fingerprint fp)
      end
    | _ ->
      match Base64.decode ~pad:false str with
      | Ok k ->
        (Wire.pubkey_of_blob (Cstruct.of_string k) >>| fun key ->
         `Key key)
      | Error (`Msg msg) ->
        Error (str ^ " is invalid or unsupported authenticator, b64 failed: " ^ msg)

let of_seed ?(typ = `RSA) seed =
  let g =
    let seed = Cstruct.of_string seed in
    Mirage_crypto_rng.(create ~seed (module Fortuna))
  in
  match typ with
  | `RSA ->
    let key = Mirage_crypto_pk.Rsa.generate ~g ~bits:2048 () in
    let public = Mirage_crypto_pk.Rsa.pub_of_priv key in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub public) in
    Log.info (fun m -> m "using ssh-rsa %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Rsa_priv key
  | `Ed25519 ->
    let key = Hacl_ed25519.priv (Mirage_crypto_rng.generate ~g 32) in
    let public = Hacl_ed25519.priv_to_public key in
    let pubkey = Wire.blob_of_pubkey (Hostkey.Ed25519_pub public) in
    Log.info (fun m -> m "using ssh-ed25519 %s"
                 (Cstruct.to_string pubkey |> Base64.encode_string));
    Hostkey.Ed25519_priv key
