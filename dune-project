(lang dune 3.6)

(name simple_krb5)

(generate_opam_files true)

(source
 (github craff/simple_krb5))

(authors "christophe@raffalli.eu")

(maintainers "christophe@raffalli.eu")

(license MIT)

(package
 (name simple_krb5)
 (synopsis "Simple bindings to kerberos")
 (description "Simple bindins to kerberos with no dependencies.")
 (depends ocaml dune)
 (tags
  (topics "krb5")))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
