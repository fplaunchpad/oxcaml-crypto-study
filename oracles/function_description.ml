(** https://dune.readthedocs.io/en/stable/foreign-code.html#a-toy-example *)

open Ctypes

module Functions (F : Ctypes.FOREIGN) = struct
  open F

  (**
      Definition from libsodium/1.0.22/include/sodium/crypto_stream_chacha20.h

      SODIUM_EXPORT
      int crypto_stream_chacha20_ietf_xor_ic(unsigned char *c, const unsigned char *m,
                                       unsigned long long mlen,
                                       const unsigned char *n, uint32_t ic,
                                       const unsigned char *k)
            __attribute__ ((nonnull(1, 4, 6)));

      *)

  let crypto_stream_chacha20_ietf_xor_ic = foreign "crypto_stream_chacha20_ietf_xor_ic" (ocaml_bytes @-> ocaml_bytes @-> ullong @-> ocaml_bytes @-> uint32_t @-> ocaml_bytes @-> returning int)

end
