
let gen_key seed typ =
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  let b64s x = Cstruct.to_string x |> Base64.encode_string in
  let seed = match seed with
    | None -> b64s (Mirage_crypto_rng.generate 30)
    | Some x -> x
  in
  let hostkey = Awa.Keys.of_seed typ seed in
  (match hostkey with
   | Awa.Hostkey.Ed25519_priv k ->
     let p = Mirage_crypto_ec.Ed25519.priv_to_cstruct k in
     Printf.printf "private key: %s:%s\n"
       Awa.Keys.(string_of_typ `Ed25519)
       (b64s p)
   | Rsa_priv _ ->
     Printf.printf "private key seed: %s:%s\n"
       Awa.Keys.(string_of_typ `Rsa) seed);
  let pub = Awa.Hostkey.pub_of_priv hostkey in
  let public = Awa.Wire.blob_of_pubkey pub in
  Printf.printf "%s %s awa@awa.local\n" (Awa.Hostkey.sshname pub) (b64s public);
  Ok ()

open Cmdliner

let seed =
  let doc = "Seed for private key." in
  Arg.(value & opt (some string) None & info [ "seed" ] ~doc)

let keytype =
  let doc = "private key type" in
  Arg.(value & opt (enum [ ("rsa", `Rsa) ; ("ed25519", `Ed25519) ]) `Rsa & info [ "keytype" ] ~doc)

let cmd =
  let info = Cmd.info "awa_gen_key" ~version:"%%VERSION_NUM%%"
  and term = Term.(term_result (const gen_key $ seed $ keytype))
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
