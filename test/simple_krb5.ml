include Krb5

let _ = Printf.printf "Krb5.is_thread_safe(): %b\n%!" (is_thread_safe ())

let _secure_context = init_context(true)
let context = init_context(false)

let p1 = parse_name ~context "raffalli@RAFFALLI"

let _ = Printf.printf "principal %a@%s\n"
          (fun ch -> Array.iteri (fun i ->
                         Printf.fprintf ch "%s%s" (if i > 0 then "|" else "")))
          (principal_data p1)
          (principal_realm p1)

let keytab = kt_resolve ~context ()

let _named_keytab = kt_resolve ~context ~name:"toto" ()

let password = Printf.printf "password: %!"; input_line stdin

let ccache = cc_resolve ~context ()

let creds1 = get_init_creds_password ~principal:p1 ~keytab ~ccache password

let _ = Printf.printf "ticket: '%S'\n%!" (ticket_string_from_creds creds1)

let _creds2 =
  try ignore (get_init_creds_keytab ~principal:p1 ~ccache keytab); ()
  with _ -> ()

let _ = Gc.full_major(); Gc.full_major()
