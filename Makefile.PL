use ExtUtils::MakeMaker;

WriteMakefile(
    NAME         => 'Crypt::PQClean::Sign',
    VERSION_FROM => 'lib/Crypt/PQClean/Sign.pm',
    LIBS         => '',
    INC          => '-Ipqclean/common',
    CCFLAGS      => '-o $@ -g -O0',
    OBJECT       => 'PQClean.o ' . join(' ', map { s/c$/o/r } <pqclean/crypto_sign/falcon-512/clean/*.c>, <pqclean/common/*.c>),
    clean        => { FILES => 'Crypt-PQClean-Sign-*' },
);
