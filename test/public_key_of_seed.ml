let () =
  match Awa.Keys.of_string Sys.argv.(1) with
  | Ok pk ->
    let pub = Awa.Hostkey.pub_of_priv pk in
    let public = Awa.Wire.blob_of_pubkey pub in
    Format.printf "%s %s awa@awa.local\n%!"
      (Awa.Hostkey.sshname pub)
      (Base64.encode_string public)
  | Error (`Msg err) ->
    Format.eprintf "%s: %s.\n%!" Sys.argv.(0) err ;
    exit 1
