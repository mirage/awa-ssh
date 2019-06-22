
open Rresult.R.Infix

type authenticator = [
  | `No_authentication
  | `Key of Nocrypto.Rsa.pub
  | `Fingerprint of string
]

let hostkey_matches a = function
  | Hostkey.Unknown -> false
  | Hostkey.Rsa_pub pub ->
    let hash = Nocrypto.Hash.SHA256.digest (Wire.blob_of_pubkey (Hostkey.Rsa_pub pub))  in
    Logs.app (fun m -> m "authenticating RSA server fingerprint SHA256:%s"
                 (Base64.encode_string ~pad:false (Cstruct.to_string hash)));
    match a with
    | `No_authentication ->
      Logs.warn (fun m -> m "NO AUTHENTICATOR");
      true
    | `Key pub' ->
      if pub = pub' then begin
        Logs.app (fun m -> m "host RSA key verification successful!");
        true
      end else begin
        Logs.err (fun m -> m "host RSA key verification failed");
        false
      end
    | `Fingerprint s ->
      if Cstruct.(equal (Cstruct.of_string s) hash) then begin
        Logs.app (fun m -> m "host fingerprint verification successful!");
        true
      end else begin
        Logs.err (fun m -> m "host fingerprint verification failed");
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
        (Wire.pubkey_of_blob (Cstruct.of_string k) >>= function
          | Hostkey.Rsa_pub key -> Ok (`Key key)
          | Hostkey.Unknown -> Error "invalid authenticator")
      | Error (`Msg msg) ->
        Error (str ^ " is invalid or unsupported authenticator, b64 failed: " ^ msg)

let of_seed seed =
  let g =
    let seed = Cstruct.of_string seed in
    Nocrypto.Rng.(create ~seed (module Generators.Fortuna))
  in
  let key = Nocrypto.Rsa.generate ~g 2048 in
  let public = Nocrypto.Rsa.pub_of_priv key in
  let pubkey = Wire.blob_of_pubkey (Hostkey.Rsa_pub public) in
  Logs.info (fun m -> m "using ssh-rsa %s"
               (Cstruct.to_string (Nocrypto.Base64.encode pubkey)));
  Hostkey.Rsa_priv key
