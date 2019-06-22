
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

let host_key = function
  | None -> Ok Hostkey.Unknown
  | Some x ->
    match Nocrypto.Base64.decode (Cstruct.of_string x) with
    | None -> Error "couldn't decode key"
    | Some k -> Wire.pubkey_of_blob k
