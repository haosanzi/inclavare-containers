make clean -C libenclave/internal/runtime/pal/skeleton
#&& make rune DEBUG=1 &&
    make skeleton -j8 && \
cp -f libenclave/internal/runtime/pal/skeleton/liberpal-skeleton-*.so /usr/lib

cp -f libenclave/internal/runtime/pal/skeleton/encl.bin \
libenclave/internal/runtime/pal/skeleton/encl.ss \
libenclave/internal/runtime/pal/skeleton/Wolfssl_Enclave.signed.so \
bundle-skeleton/rootfs/run/rune

rm -rf bundle-skeleton/rootfs/run/rune/ra-tls.sock
rm -rf /run/rune/ra-tls.sock
./rune --debug run -b bundle-skeleton 3assshsu
